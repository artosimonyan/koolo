package character

import (
	"fmt"
	"log/slog"
	"math"
	"sort"
	"time"

	"github.com/hectorgimenez/d2go/pkg/data"
	"github.com/hectorgimenez/d2go/pkg/data/npc"
	"github.com/hectorgimenez/d2go/pkg/data/skill"
	"github.com/hectorgimenez/d2go/pkg/data/stat"
	"github.com/hectorgimenez/d2go/pkg/data/state"
	"github.com/hectorgimenez/koolo/internal/action/step"
	"github.com/hectorgimenez/koolo/internal/context"
	"github.com/hectorgimenez/koolo/internal/game"
	"github.com/hectorgimenez/koolo/internal/pather"
)

const (
	sorceressMaxAttacksLoop         = 40
	minBlizzSorceressAttackDistance = 8
	maxBlizzSorceressAttackDistance = 16
	dangerDistance                  = 8  // Monsters closer than this are considered dangerous
	safeDistance                    = 10 // Distance to teleport away to
)

type BlizzardSorceress struct {
	BaseCharacter
}

func (s BlizzardSorceress) CheckKeyBindings() []skill.ID {
	requireKeybindings := []skill.ID{skill.Blizzard, skill.Teleport, skill.TomeOfTownPortal, skill.ShiverArmor, skill.StaticField}
	missingKeybindings := []skill.ID{}

	for _, cskill := range requireKeybindings {
		if _, found := s.Data.KeyBindings.KeyBindingForSkill(cskill); !found {
			switch cskill {
			// Since we can have one of 3 armors:
			case skill.ShiverArmor:
				_, found1 := s.Data.KeyBindings.KeyBindingForSkill(skill.FrozenArmor)
				_, found2 := s.Data.KeyBindings.KeyBindingForSkill(skill.ChillingArmor)
				if !found1 && !found2 {
					missingKeybindings = append(missingKeybindings, skill.ShiverArmor)
				}
			default:
				missingKeybindings = append(missingKeybindings, cskill)
			}
		}
	}

	if len(missingKeybindings) > 0 {
		s.Logger.Debug("There are missing required key bindings.", slog.Any("Bindings", missingKeybindings))
	}

	return missingKeybindings
}

func (s BlizzardSorceress) KillMonsterSequence(
	monsterSelector func(d game.Data) (data.UnitID, bool),
	skipOnImmunities []stat.Resist,
) error {
	completedAttackLoops := 0
	previousUnitID := 0
	lastReposition := time.Now()

	attackOpts := step.StationaryDistance(minBlizzSorceressAttackDistance, maxBlizzSorceressAttackDistance)

	for {
		// First check if we need to reposition due to nearby monsters
		needsRepos, dangerousMonster := s.needsRepositioning()
		if needsRepos && time.Since(lastReposition) > time.Second*1 {
			lastReposition = time.Now()

			// Get the target monster ID
			targetID, found := monsterSelector(*s.Data)
			if !found {
				return nil
			}

			// Find the monster
			targetMonster, found := s.Data.Monsters.FindByID(targetID)
			if !found {
				s.Logger.Info("Target monster not found for repositioning")
				return nil
			}

			s.Logger.Info(fmt.Sprintf("Dangerous monster detected at distance %d, repositioning...",
			pather.DistanceFromPoint(s.Data.PlayerUnit.Position, dangerousMonster.Position)))

			// Find a safe position
			safePos, found := s.findSafePosition(targetMonster)
			if found {
				step.MoveTo(safePos)
			} else {
				s.Logger.Info("Could not find safe position for repositioning")
			}
		}

		// Get the monster to attack
		id, found := monsterSelector(*s.Data)
		if !found {
			return nil
		}

		// If the monster has changed, reset the attack loop counter
		if previousUnitID != int(id) {
			completedAttackLoops = 0
		}

		if !s.preBattleChecks(id, skipOnImmunities) {
			return nil
		}

		// If we've exceeded the maximum number of attacks, finish the loop.
		if completedAttackLoops >= sorceressMaxAttacksLoop {
			return nil
		}

		monster, found := s.Data.Monsters.FindByID(id)
		if !found {
			s.Logger.Info("Monster not found", slog.String("monster", fmt.Sprintf("%v", monster)))
			return nil
		}

		// If we're on cooldown, attack with a primary attack
		if s.Data.PlayerUnit.States.HasState(state.Cooldown) {
			step.PrimaryAttack(id, 2, true, attackOpts)
		}

		step.SecondaryAttack(skill.Blizzard, id, 1, attackOpts)

		completedAttackLoops++
		previousUnitID = int(id)
	}
}

func (s BlizzardSorceress) killMonster(npc npc.ID, t data.MonsterType) error {
	return s.KillMonsterSequence(func(d game.Data) (data.UnitID, bool) {
		m, found := d.Monsters.FindOne(npc, t)
		if !found {
			return 0, false
		}

		return m.UnitID, true
	}, nil)
}

func (s BlizzardSorceress) killMonsterByName(id npc.ID, monsterType data.MonsterType, skipOnImmunities []stat.Resist) error {
	// while the monster is alive, keep attacking it
	for {
		if m, found := s.Data.Monsters.FindOne(id, monsterType); found {
			if m.Stats[stat.Life] <= 0 {
				break
			}

			s.KillMonsterSequence(func(d game.Data) (data.UnitID, bool) {
				if m, found := d.Monsters.FindOne(id, monsterType); found {
					return m.UnitID, true
				}

				return 0, false
			}, skipOnImmunities)
		} else {
			break
		}
	}
	return nil
}

func (s BlizzardSorceress) BuffSkills() []skill.ID {
	skillsList := make([]skill.ID, 0)
	if _, found := s.Data.KeyBindings.KeyBindingForSkill(skill.EnergyShield); found {
		skillsList = append(skillsList, skill.EnergyShield)
	}

	armors := []skill.ID{skill.ChillingArmor, skill.ShiverArmor, skill.FrozenArmor}
	for _, armor := range armors {
		if _, found := s.Data.KeyBindings.KeyBindingForSkill(armor); found {
			skillsList = append(skillsList, armor)
			return skillsList
		}
	}

	return skillsList
}

func (s BlizzardSorceress) PreCTABuffSkills() []skill.ID {
	return []skill.ID{}
}

func (s BlizzardSorceress) KillCountess() error {
	return s.killMonsterByName(npc.DarkStalker, data.MonsterTypeSuperUnique, nil)
}

func (s BlizzardSorceress) KillAndariel() error {
	return s.killMonsterByName(npc.Andariel, data.MonsterTypeUnique, nil)
}

func (s BlizzardSorceress) KillSummoner() error {
	return s.killMonsterByName(npc.Summoner, data.MonsterTypeUnique, nil)
}

func (s BlizzardSorceress) KillDuriel() error {
	return s.killMonsterByName(npc.Duriel, data.MonsterTypeUnique, nil)
}

func (s BlizzardSorceress) KillCouncil() error {
	return s.KillMonsterSequence(func(d game.Data) (data.UnitID, bool) {
		// Exclude monsters that are not council members
		var councilMembers []data.Monster
		var coldImmunes []data.Monster
		for _, m := range d.Monsters.Enemies() {
			if m.Name == npc.CouncilMember || m.Name == npc.CouncilMember2 || m.Name == npc.CouncilMember3 {
				if m.IsImmune(stat.ColdImmune) {
					coldImmunes = append(coldImmunes, m)
				} else {
					councilMembers = append(councilMembers, m)
				}
			}
		}

		councilMembers = append(councilMembers, coldImmunes...)

		for _, m := range councilMembers {
			return m.UnitID, true
		}

		return 0, false
	}, nil)
}

func (s BlizzardSorceress) KillMephisto() error {
	return s.killMonsterByName(npc.Mephisto, data.MonsterTypeUnique, nil)
}

func (s BlizzardSorceress) KillIzual() error {
	m, _ := s.Data.Monsters.FindOne(npc.Izual, data.MonsterTypeUnique)
	_ = step.SecondaryAttack(skill.StaticField, m.UnitID, 4, step.Distance(5, 8))

	return s.killMonsterByName(npc.Izual, data.MonsterTypeUnique, nil)
}

func (s BlizzardSorceress) KillDiablo() error {
	timeout := time.Second * 20
	startTime := time.Now()
	diabloFound := false

	for {
		if time.Since(startTime) > timeout && !diabloFound {
			s.Logger.Error("Diablo was not found, timeout reached")
			return nil
		}

		diablo, found := s.Data.Monsters.FindOne(npc.Diablo, data.MonsterTypeUnique)
		if !found || diablo.Stats[stat.Life] <= 0 {
			// Already dead
			if diabloFound {
				return nil
			}

			// Keep waiting...
			time.Sleep(200)
			continue
		}

		diabloFound = true
		s.Logger.Info("Diablo detected, attacking")

		_ = step.SecondaryAttack(skill.StaticField, diablo.UnitID, 5, step.Distance(3, 8))

		return s.killMonsterByName(npc.Diablo, data.MonsterTypeUnique, nil)
	}
}

func (s BlizzardSorceress) KillPindle() error {
	return s.killMonsterByName(npc.DefiledWarrior, data.MonsterTypeSuperUnique, s.CharacterCfg.Game.Pindleskin.SkipOnImmunities)
}

func (s BlizzardSorceress) KillNihlathak() error {
	return s.killMonsterByName(npc.Nihlathak, data.MonsterTypeSuperUnique, nil)
}

func (s BlizzardSorceress) KillBaal() error {
	m, _ := s.Data.Monsters.FindOne(npc.BaalCrab, data.MonsterTypeUnique)
	step.SecondaryAttack(skill.StaticField, m.UnitID, 4, step.Distance(5, 8))

	return s.killMonsterByName(npc.BaalCrab, data.MonsterTypeUnique, nil)
}

func (s BlizzardSorceress) needsRepositioning() (bool, data.Monster) {
	for _, monster := range s.Data.Monsters.Enemies() {
		if monster.Stats[stat.Life] <= 0 {
			continue
		}

		distance := pather.DistanceFromPoint(s.Data.PlayerUnit.Position, monster.Position)
		if distance < dangerDistance {
			return true, monster
		}
	}

	return false, data.Monster{}
}

func (s BlizzardSorceress) findSafePosition(targetMonster data.Monster) (data.Position, bool) {
	ctx := context.Get()
	playerPos := s.Data.PlayerUnit.Position

	// Define a stricter minimum safe distance from monsters
	const minSafeMonsterDistance = 5

	// Generate candidate positions in a circle around the player
	candidatePositions := []data.Position{}

	// First try positions in the opposite direction from the dangerous monster
	vectorX := playerPos.X - targetMonster.Position.X
	vectorY := playerPos.Y - targetMonster.Position.Y

	// Normalize the vector
	length := math.Sqrt(float64(vectorX*vectorX + vectorY*vectorY))
	if length > 0 {
		normalizedX := int(float64(vectorX) / length * float64(safeDistance))
		normalizedY := int(float64(vectorY) / length * float64(safeDistance))

		// Add positions in the opposite direction with some variation
		for offsetX := -3; offsetX <= 3; offsetX++ {
			for offsetY := -3; offsetY <= 3; offsetY++ {
				candidatePos := data.Position{
					X: playerPos.X + normalizedX + offsetX,
					Y: playerPos.Y + normalizedY + offsetY,
				}

				if s.Data.AreaData.IsWalkable(candidatePos) {
					candidatePositions = append(candidatePositions, candidatePos)
				}
			}
		}
	}

	// Generate positions in a circle with smaller angle increments for more candidates
	// Try positions in different directions around the player
	for angle := 0; angle < 360; angle += 5 {
		radians := float64(angle) * math.Pi / 180

		// Try multiple distances from the player
		for distance := minSafeMonsterDistance; distance <= safeDistance+5; distance += 2 {
			dx := int(math.Cos(radians) * float64(distance))
			dy := int(math.Sin(radians) * float64(distance))

			basePos := data.Position{
				X: playerPos.X + dx,
				Y: playerPos.Y + dy,
			}

			// Check a small area around the base position
			for offsetX := -1; offsetX <= 1; offsetX++ {
				for offsetY := -1; offsetY <= 1; offsetY++ {
					candidatePos := data.Position{
						X: basePos.X + offsetX,
						Y: basePos.Y + offsetY,
					}

					if s.Data.AreaData.IsWalkable(candidatePos) {
						candidatePositions = append(candidatePositions, candidatePos)
					}
				}
			}
		}
	}

	// No walkable positions found
	if len(candidatePositions) == 0 {
		return data.Position{}, false
	}

	// Evaluate all candidate positions
	type scoredPosition struct {
		pos   data.Position
		score float64
	}

	scoredPositions := []scoredPosition{}

	for _, pos := range candidatePositions {
		// Check if this position has line of sight to target
		if !ctx.PathFinder.LineOfSight(pos, targetMonster.Position) {
			continue
		}

		// Calculate minimum distance to any monster
		minMonsterDistance := math.MaxFloat64
		for _, monster := range s.Data.Monsters.Enemies() {
			if monster.Stats[stat.Life] <= 0 {
				continue
			}

			monsterDistance := pather.DistanceFromPoint(pos, monster.Position)
			if float64(monsterDistance) < minMonsterDistance {
				minMonsterDistance = float64(monsterDistance)
			}
		}

		// Strictly skip positions that are too close to monsters
		if minMonsterDistance < minSafeMonsterDistance {
			continue
		}

		// Calculate distance to target monster
		targetDistance := pather.DistanceFromPoint(pos, targetMonster.Position)

		// Score the position based on multiple factors:
		// 1. Distance from monsters (higher is better, with a strong preference for safety)
		// 2. Distance to target (should be in attack range)
		// 3. Distance from current position (closer is better for quick repositioning)
		distanceFromPlayer := pather.DistanceFromPoint(pos, playerPos)

		// Calculate attack range score (highest when in optimal attack range)
		attackRangeScore := 0.0
		if targetDistance >= minBlizzSorceressAttackDistance && targetDistance <= maxBlizzSorceressAttackDistance {
			attackRangeScore = 10.0
		} else {
			// Penalize positions outside attack range
			attackRangeScore = -math.Abs(float64(targetDistance) - float64(minBlizzSorceressAttackDistance+maxBlizzSorceressAttackDistance)/2.0)
		}

		// Final score calculation - heavily weight monster distance for safety
		score := minMonsterDistance*3.0 + attackRangeScore*2.0 - float64(distanceFromPlayer)*0.5

		// Extra bonus for positions that are very safe (far from monsters)
		if minMonsterDistance > float64(dangerDistance) {
			score += 5.0
		}

		scoredPositions = append(scoredPositions, scoredPosition{
			pos:   pos,
			score: score,
		})
	}

	// Sort positions by score (highest first)
	sort.Slice(scoredPositions, func(i, j int) bool {
		return scoredPositions[i].score > scoredPositions[j].score
	})

	// Return the best position if we found any
	if len(scoredPositions) > 0 {
		s.Logger.Info(fmt.Sprintf("Found safe position with score %.2f at distance %.2f from nearest monster",
			scoredPositions[0].score, minMonsterDistance(scoredPositions[0].pos, s.Data.Monsters)))
		return scoredPositions[0].pos, true
	}

	return data.Position{}, false
}

// Helper function to calculate minimum monster distance
func minMonsterDistance(pos data.Position, monsters data.Monsters) float64 {
	minDistance := math.MaxFloat64
	for _, monster := range monsters.Enemies() {
		if monster.Stats[stat.Life] <= 0 {
			continue
		}

		distance := pather.DistanceFromPoint(pos, monster.Position)
		if float64(distance) < minDistance {
			minDistance = float64(distance)
		}
	}
	return minDistance
}
