package bot

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/hectorgimenez/d2go/pkg/data"
	"github.com/hectorgimenez/d2go/pkg/nip"
	"github.com/hectorgimenez/koolo/cmd/koolo/log"
	"github.com/hectorgimenez/koolo/internal/character"
	"github.com/hectorgimenez/koolo/internal/config"
	"github.com/hectorgimenez/koolo/internal/context"
	"github.com/hectorgimenez/koolo/internal/event"
	"github.com/hectorgimenez/koolo/internal/game"
	"github.com/hectorgimenez/koolo/internal/health"
	"github.com/hectorgimenez/koolo/internal/pather"
	"github.com/hectorgimenez/koolo/internal/utils"
	"github.com/hectorgimenez/koolo/internal/utils/winproc"
	"github.com/lxn/win"
)

type SupervisorManager struct {
	logger         *slog.Logger
	supervisors    map[string]Supervisor
	crashDetectors map[string]*game.CrashDetector
	eventListener  *event.Listener
}
type ConfigReloadResult struct {
	Success      bool
	ReloadErrors map[string]error // Per-supervisor errors
	GlobalError  error            // Critical errors that prevented reload
}

func NewSupervisorManager(logger *slog.Logger, eventListener *event.Listener) *SupervisorManager {
	return &SupervisorManager{
		logger:         logger,
		supervisors:    make(map[string]Supervisor),
		crashDetectors: make(map[string]*game.CrashDetector),
		eventListener:  eventListener,
	}
}

func (mng *SupervisorManager) AvailableSupervisors() []string {
	availableSupervisors := make([]string, 0)
	for name := range config.Characters {
		if name != "template" {
			availableSupervisors = append(availableSupervisors, name)
		}
	}

	return availableSupervisors
}

func (mng *SupervisorManager) Start(supervisorName string, attachToExisting bool, pidHwnd ...uint32) error {
	// Avoid multiple instances of the supervisor - shitstorm prevention
	if _, exists := mng.supervisors[supervisorName]; exists {
		return fmt.Errorf("supervisor %s is already running", supervisorName)
	}

	// Reload config to get the latest local changes before starting the supervisor
	err := config.Load()
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	supervisorLogger, err := log.NewLogger(config.Koolo.Debug.Log, config.Koolo.LogSaveDirectory, supervisorName)
	if err != nil {
		return err
	}

	var optionalPID uint32
	var optionalHWND win.HWND

	if attachToExisting {
		if len(pidHwnd) == 2 {
			mng.logger.Info("Attaching to existing game", "pid", pidHwnd[0], "hwnd", pidHwnd[1])
			optionalPID = pidHwnd[0]
			optionalHWND = win.HWND(pidHwnd[1])
		} else {
			return fmt.Errorf("pid and hwnd are required when attaching to an existing game")
		}
	}

	supervisor, crashDetector, err := mng.buildSupervisor(supervisorName, supervisorLogger, attachToExisting, optionalPID, optionalHWND)
	if err != nil {
		return err
	}

	if oldCrashDetector, exists := mng.crashDetectors[supervisorName]; exists {
		oldCrashDetector.Stop() // Stop the old crash detector if it exists
	}

	mng.supervisors[supervisorName] = supervisor
	mng.crashDetectors[supervisorName] = crashDetector

	if config.Koolo.GameWindowArrangement {
		go func() {
			// When the game starts, its doing some weird stuff like repositioning and resizing window automatically
			// we need to wait until this is done in order to reposition, or it will be overridden
			time.Sleep(time.Second * 5)
			mng.rearrangeWindows()
		}()
	}

	// Start the Crash Detector in a thread to avoid blocking and speed up start
	go crashDetector.Start()

	err = supervisor.Start()
	if err != nil {
		mng.logger.Error(fmt.Sprintf("error running supervisor %s: %s", supervisorName, err.Error()))
	}

	return nil
}

func (mng *SupervisorManager) StopAll() {
	for _, s := range mng.supervisors {
		s.Stop()
	}
}

func (mng *SupervisorManager) Stop(supervisor string) {

	s, found := mng.supervisors[supervisor]
	if found {

		// Stop the Supervisor
		s.Stop()

		// Delete him from the list of Supervisors
		delete(mng.supervisors, supervisor)

		if cd, ok := mng.crashDetectors[supervisor]; ok {
			cd.Stop()
			delete(mng.crashDetectors, supervisor)
		}
	}
}

func (mng *SupervisorManager) TogglePause(supervisor string) {
	s, found := mng.supervisors[supervisor]
	if found {
		s.TogglePause()
	}
}

func (mng *SupervisorManager) Status(characterName string) Stats {
	for name, supervisor := range mng.supervisors {
		if name == characterName {
			return supervisor.Stats()
		}
	}

	return Stats{}
}

func (mng *SupervisorManager) GetData(characterName string) *game.Data {
	for name, supervisor := range mng.supervisors {
		if name == characterName {
			return supervisor.GetData()
		}
	}

	return nil
}

func (mng *SupervisorManager) GetContext(characterName string) *context.Context {
	for name, supervisor := range mng.supervisors {
		if name == characterName {
			return supervisor.GetContext()
		}
	}

	return nil
}

func (mng *SupervisorManager) buildSupervisor(supervisorName string, logger *slog.Logger, attach bool, optionalPID uint32, optionalHWND win.HWND) (Supervisor, *game.CrashDetector, error) {
	cfg, found := config.Characters[supervisorName]
	if !found {
		return nil, nil, fmt.Errorf("character %s not found", supervisorName)
	}

	var pid uint32
	var hwnd win.HWND

	if attach {
		if optionalPID != 0 && optionalHWND != 0 {
			pid = optionalPID
			hwnd = optionalHWND
		} else {
			return nil, nil, fmt.Errorf("pid and hwnd are required when attaching to an existing game")
		}
	} else {
		var err error
		pid, hwnd, err = game.StartGame(cfg.Username, cfg.Password, cfg.AuthMethod, cfg.AuthToken, cfg.Realm, cfg.CommandLineArgs, config.Koolo.UseCustomSettings)
		if err != nil {
			return nil, nil, fmt.Errorf("error starting game: %w", err)
		}
	}

	gr, err := game.NewGameReader(cfg, supervisorName, pid, hwnd, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating game reader: %w", err)
	}

	gi, err := game.InjectorInit(logger, gr.GetPID())
	if err != nil {
		return nil, nil, fmt.Errorf("error creating game injector: %w", err)
	}

	ctx := context.NewContext(supervisorName)

	hidM := game.NewHID(gr, gi)
	pf := pather.NewPathFinder(gr, ctx.Data, hidM, cfg)

	bm := health.NewBeltManager(ctx.Data, hidM, logger, supervisorName)
	hm := health.NewHealthManager(bm, ctx.Data)

	ctx.CharacterCfg = cfg
	ctx.EventListener = mng.eventListener
	ctx.HID = hidM
	ctx.Logger = logger
	ctx.Manager = game.NewGameManager(gr, hidM, supervisorName)
	ctx.GameReader = gr
	ctx.MemoryInjector = gi
	ctx.PathFinder = pf
	ctx.BeltManager = bm
	ctx.HealthManager = hm
	char, err := character.BuildCharacter(ctx.Context)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating character: %w", err)
	}
	ctx.Char = char

	bot := NewBot(ctx.Context)

	statsHandler := NewStatsHandler(supervisorName, logger)
	mng.eventListener.Register(statsHandler.Handle)

	var supervisor Supervisor

	supervisor, err = NewSinglePlayerSupervisor(supervisorName, bot, statsHandler)

	if err != nil {
		return nil, nil, err

	}

	// This function will be used to restart the client - passed to the crashDetector
	restartFunc := func() {
		mng.logger.Info("Restarting supervisor after crash", slog.String("supervisor", supervisorName))
		mng.Stop(supervisorName)
		time.Sleep(5 * time.Second) // Wait a bit before restarting

		// Get a list of all available Supervisors
		supervisorList := mng.AvailableSupervisors()

		for {

			// Set the default state
			tokenAuthStarting := false

			// Get the current supervisor's config
			supCfg := config.Characters[supervisorName]

			for _, sup := range supervisorList {

				// If the current don't check against the one we're trying to launch
				if sup == supervisorName {
					continue
				}

				if mng.GetSupervisorStats(sup).SupervisorStatus == Starting {
					if supCfg.AuthMethod == "TokenAuth" {
						tokenAuthStarting = true
						mng.logger.Info("Waiting before restart as another client is already starting and we're using token auth", slog.String("supervisor", sup))
						break
					}

					sCfg, found := config.Characters[sup]
					if found {
						if sCfg.AuthMethod == "TokenAuth" {
							// A client that uses token auth is currently starting, hold off restart
							tokenAuthStarting = true
							mng.logger.Info("Waiting before restart as a client that's using token auth is already starting", slog.String("supervisor", sup))
							break
						}
					}
				}
			}

			if !tokenAuthStarting {
				break
			}

			// Wait 5 seconds before checking again
			utils.Sleep(5000)
		}

		gameTitle := "D2R - [" + strconv.FormatInt(int64(pid), 10) + "] - " + supervisorName + " - " + cfg.Realm
		winproc.SetWindowText.Call(uintptr(hwnd), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(gameTitle))))

		err := mng.Start(supervisorName, false)
		if err != nil {
			mng.logger.Error("Failed to restart supervisor", slog.String("supervisor", supervisorName), slog.String("Error: ", err.Error()))
		}
	}

	gameTitle := "D2R - [" + strconv.FormatInt(int64(pid), 10) + "] - " + supervisorName + " - " + cfg.Realm
	winproc.SetWindowText.Call(uintptr(hwnd), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(gameTitle))))
	crashDetector := game.NewCrashDetector(supervisorName, int32(pid), uintptr(hwnd), mng.logger, restartFunc)

	return supervisor, crashDetector, nil
}

func (mng *SupervisorManager) GetSupervisorStats(supervisor string) Stats {
	if mng.supervisors[supervisor] == nil {
		return Stats{}
	}
	return mng.supervisors[supervisor].Stats()
}

func (mng *SupervisorManager) rearrangeWindows() {
	width := win.GetSystemMetrics(0)
	height := win.GetSystemMetrics(1)
	var windowBorderX int32 = 2   // left + right window border is 2px
	var windowBorderY int32 = 40  // upper window border is usually 40px
	var windowOffsetX int32 = -10 // offset horizontal window placement by -10 pixel
	maxColumns := width / (1280 + windowBorderX)
	maxRows := height / (720 + windowBorderY)

	mng.logger.Debug(
		"Arranging windows",
		slog.String("displaywidth", strconv.FormatInt(int64(width), 10)),
		slog.String("displayheight", strconv.FormatInt(int64(height), 10)),
		slog.String("max columns", strconv.FormatInt(int64(maxColumns+1), 10)), // +1 as we are counting from 0
		slog.String("max rows", strconv.FormatInt(int64(maxRows+1), 10)),
	)

	var column, row int32
	for _, sp := range mng.supervisors {
		// reminder that columns are vertical (they go up and down) and rows are horizontal (they go left and right)
		if column > maxColumns {
			column = 0
			row++
		}

		if row <= maxRows {
			sp.SetWindowPosition(int(column*(1280+windowBorderX)+windowOffsetX), int(row*(720+windowBorderY)))
			mng.logger.Debug(
				"Window Positions",
				slog.String("supervisor", sp.Name()),
				slog.String("column", strconv.FormatInt(int64(column), 10)),
				slog.String("row", strconv.FormatInt(int64(row), 10)),
				slog.String("position", strconv.FormatInt(int64(column*(1280+windowBorderX)+windowOffsetX), 10)+"x"+strconv.FormatInt(int64(row*(720+windowBorderY)), 10)),
			)
			column++
		} else {
			mng.logger.Debug("Window position of supervisor " + sp.Name() + " was not changed, no free space for it")
		}
	}
}

func (mng *SupervisorManager) ReloadConfig() ConfigReloadResult {
	result := ConfigReloadResult{
		Success:      true,
		ReloadErrors: make(map[string]error),
	}

	// Load fresh configs
	if err := config.Load(); err != nil {
		return ConfigReloadResult{
			Success:     false,
			GlobalError: fmt.Errorf("failed to load new configs: %w", err),
		}
	}

	// Apply new configs to running supervisors
	for name, sup := range mng.supervisors {
		newCfg, exists := config.Characters[name]
		if !exists {
			continue
		}

		ctx := sup.GetContext()
		if ctx == nil {
			continue
		}

		// Preserve runtime data
		oldRuntimeData := ctx.CharacterCfg.Runtime

		// Update the config
		*ctx.CharacterCfg = *newCfg
		ctx.CharacterCfg.Runtime = oldRuntimeData
	}

	return result
}

// Add a new applyNewConfig helper function:
func applyNewConfig(ctx *context.Context, newCfg *config.CharacterCfg) error {
	var pickitPath string
	if config.Koolo.CentralizedPickitPath != "" && newCfg.UseCentralizedPickit {
		pickitPath = config.Koolo.CentralizedPickitPath + "\\"
		ctx.Logger.Debug("Using centralized pickit path", "path", pickitPath)
	} else {
		pickitPath = filepath.Join("config", ctx.Name, "pickit") + "\\"
		ctx.Logger.Debug("Using local pickit path", "path", pickitPath)
	}

	// Reload pickit rules
	rules, err := nip.ReadDir(pickitPath)
	if err != nil {
		return fmt.Errorf("failed to reload pickit rules: %w", err)
	}

	// Load leveling pickit if needed
	if len(newCfg.Game.Runs) > 0 && newCfg.Game.Runs[0] == "leveling" {
		levelingPickitPath := filepath.Join("config", ctx.Name, "pickit_leveling") + "\\"
		levelingRules, err := nip.ReadDir(levelingPickitPath)
		if err != nil {
			return fmt.Errorf("failed to reload leveling pickit rules: %w", err)
		}
		rules = append(rules, levelingRules...)
	}

	// Create a completely new config instance
	cfgCopy := &config.CharacterCfg{
		MaxGameLength:        newCfg.MaxGameLength,
		Username:             newCfg.Username,
		Password:             newCfg.Password,
		AuthMethod:           newCfg.AuthMethod,
		AuthToken:            newCfg.AuthToken,
		Realm:                newCfg.Realm,
		CharacterName:        newCfg.CharacterName,
		CommandLineArgs:      newCfg.CommandLineArgs,
		KillD2OnStop:         newCfg.KillD2OnStop,
		ClassicMode:          newCfg.ClassicMode,
		CloseMiniPanel:       newCfg.CloseMiniPanel,
		UseCentralizedPickit: newCfg.UseCentralizedPickit,
		Scheduler:            newCfg.Scheduler,
		Health:               newCfg.Health,
		Inventory:            newCfg.Inventory,
		Character: struct {
			Class         string `yaml:"class"`
			UseMerc       bool   `yaml:"useMerc"`
			StashToShared bool   `yaml:"stashToShared"`
			UseTeleport   bool   `yaml:"useTeleport"`
			BerserkerBarb struct {
				FindItemSwitch              bool `yaml:"find_item_switch"`
				SkipPotionPickupInTravincal bool `yaml:"skip_potion_pickup_in_travincal"`
			} `yaml:"berserker_barb"`
			NovaSorceress struct {
				BossStaticThreshold int `yaml:"boss_static_threshold"`
			} `yaml:"nova_sorceress"`
			MosaicSin struct {
				UseTigerStrike    bool `yaml:"useTigerStrike"`
				UseCobraStrike    bool `yaml:"useCobraStrike"`
				UseClawsOfThunder bool `yaml:"useClawsOfThunder"`
				UseBladesOfIce    bool `yaml:"useBladesOfIce"`
				UseFistsOfFire    bool `yaml:"useFistsOfFire"`
			} `yaml:"mosaic_sin"`
		}{
			Class:         newCfg.Character.Class,
			UseMerc:       newCfg.Character.UseMerc,
			StashToShared: newCfg.Character.StashToShared,
			UseTeleport:   newCfg.Character.UseTeleport,
			BerserkerBarb: newCfg.Character.BerserkerBarb,
			NovaSorceress: newCfg.Character.NovaSorceress,
			MosaicSin:     newCfg.Character.MosaicSin,
		},
		Game:        newCfg.Game,
		Companion:   newCfg.Companion,
		Gambling:    newCfg.Gambling,
		CubeRecipes: newCfg.CubeRecipes,
		BackToTown:  newCfg.BackToTown,
		Runtime: struct {
			Rules nip.Rules   `yaml:"-"`
			Drops []data.Item `yaml:"-"`
		}{
			Rules: rules,
			Drops: newCfg.Runtime.Drops,
		},
	}

	// Log the config values for debugging
	ctx.Logger.Debug("Config values before update",
		"currentUseTeleport", ctx.CharacterCfg.Character.UseTeleport,
		"newUseTeleport", cfgCopy.Character.UseTeleport)

	// Update the context configuration
	ctx.CharacterCfg = cfgCopy

	ctx.Logger.Debug("Config values after update",
		"useTeleport", ctx.CharacterCfg.Character.UseTeleport,
		"ruleCount", len(rules))

	// Also update the global config to ensure it stays in sync
	config.Characters[ctx.Name] = cfgCopy

	return nil
}

func validateConfigForSupervisor(sup Supervisor, cfg *config.CharacterCfg) error {
	if cfg == nil {
		return errors.New("nil configuration")
	}

	// Validate critical fields
	if cfg.CharacterName == "" {
		return errors.New("character name cannot be empty")
	}

	// Validate pickit configuration
	if cfg.UseCentralizedPickit {
		if config.Koolo.CentralizedPickitPath == "" {
			return errors.New("centralized pickit enabled but no path configured")
		}
		if _, err := os.Stat(config.Koolo.CentralizedPickitPath); os.IsNotExist(err) {
			return fmt.Errorf("centralized pickit path does not exist: %s", config.Koolo.CentralizedPickitPath)
		}
	}

	// Validate health settings
	if cfg.Health.ChickenAt <= 0 || cfg.Health.ChickenAt > 100 {
		return fmt.Errorf("invalid chicken health value: %d", cfg.Health.ChickenAt)
	}

	// Validate that we have at least one run configured
	if len(cfg.Game.Runs) == 0 {
		return errors.New("no runs configured")
	}

	return nil
}
