package server

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
	"github.com/hectorgimenez/d2go/pkg/data"
	"github.com/hectorgimenez/d2go/pkg/data/area"
	"github.com/hectorgimenez/d2go/pkg/data/difficulty"
	"github.com/hectorgimenez/d2go/pkg/data/stat"
	"github.com/hectorgimenez/koolo/internal/bot"
	"github.com/hectorgimenez/koolo/internal/config"
	internalContext "github.com/hectorgimenez/koolo/internal/context"

	"github.com/hectorgimenez/koolo/internal/game"
	"github.com/hectorgimenez/koolo/internal/utils"
	"github.com/hectorgimenez/koolo/internal/utils/winproc"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

type HttpServer struct {
	logger    *slog.Logger
	server    *http.Server
	manager   *bot.SupervisorManager
	templates *template.Template
	wsServer  *WebSocketServer
}

var (
	//go:embed all:assets
	assetsFS embed.FS
	//go:embed all:templates
	templatesFS embed.FS

	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)

type Client struct {
	conn *websocket.Conn
	send chan []byte
}

type WebSocketServer struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
}
type DebugDataResponse struct {
	DebugData map[internalContext.Priority]*internalContext.Debug `json:"debugData"`
	GameData  *game.Data                                          `json:"gameData"`
}

func NewWebSocketServer() *WebSocketServer {
	return &WebSocketServer{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

type Process struct {
	WindowTitle string `json:"windowTitle"`
	ProcessName string `json:"processName"`
	PID         uint32 `json:"pid"`
}

func (s *WebSocketServer) Run() {
	for {
		select {
		case client := <-s.register:
			s.clients[client] = true
		case client := <-s.unregister:
			if _, ok := s.clients[client]; ok {
				delete(s.clients, client)
				close(client.send)
			}
		case message := <-s.broadcast:
			for client := range s.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(s.clients, client)
				}
			}
		}
	}
}

func (s *WebSocketServer) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("Failed to upgrade connection to WebSocket", "error", err)
		return
	}

	client := &Client{conn: conn, send: make(chan []byte, 256)}
	s.register <- client

	go s.writePump(client)
	go s.readPump(client)
}

func (s *WebSocketServer) writePump(client *Client) {
	defer func() {
		client.conn.Close()
	}()

	for {
		select {
		case message, ok := <-client.send:
			if !ok {
				client.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := client.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}
		}
	}
}

func (s *WebSocketServer) readPump(client *Client) {
	defer func() {
		s.unregister <- client
		client.conn.Close()
	}()

	for {
		_, _, err := client.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Error("WebSocket read error", "error", err)
			}
			break
		}
	}
}

func (s *HttpServer) BroadcastStatus() {
	for {
		data := s.getStatusData()
		jsonData, err := json.Marshal(data)
		if err != nil {
			slog.Error("Failed to marshal status data", "error", err)
			continue
		}

		s.wsServer.broadcast <- jsonData
		time.Sleep(1 * time.Second)
	}
}

func New(logger *slog.Logger, manager *bot.SupervisorManager) (*HttpServer, error) {
	var templates *template.Template
	helperFuncs := template.FuncMap{
		"isInSlice": func(slice []stat.Resist, value string) bool {
			return slices.Contains(slice, stat.Resist(value))
		},
		"isTZSelected": func(slice []area.ID, value int) bool {
			return slices.Contains(slice, area.ID(value))
		},
		"executeTemplateByName": func(name string, data interface{}) template.HTML {
			tmpl := templates.Lookup(name)
			var buf bytes.Buffer
			if tmpl == nil {
				return "This run is not configurable."
			}

			tmpl.Execute(&buf, data)
			return template.HTML(buf.String())
		},
		"qualityClass": qualityClass,
		"statIDToText": statIDToText,
		"contains":     containss,
		"seq": func(start, end int) []int {
			var result []int
			for i := start; i <= end; i++ {
				result = append(result, i)
			}
			return result
		},
	}
	templates, err := template.New("").Funcs(helperFuncs).ParseFS(templatesFS, "templates/*.gohtml")
	if err != nil {
		return nil, err
	}

	return &HttpServer{
		logger:    logger,
		manager:   manager,
		templates: templates,
	}, nil
}

func (s *HttpServer) getProcessList(w http.ResponseWriter, r *http.Request) {
	processes, err := getRunningProcesses()
	if err != nil {
		http.Error(w, "Failed to get process list", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(processes)
}

func (s *HttpServer) attachProcess(w http.ResponseWriter, r *http.Request) {
	characterName := r.URL.Query().Get("characterName")
	pidStr := r.URL.Query().Get("pid")

	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		s.logger.Error("Invalid PID", "error", err)
		return
	}

	// Find the main window handle (HWND) for the process
	var hwnd win.HWND
	enumWindowsCallback := func(h win.HWND, param uintptr) uintptr {
		var processID uint32
		win.GetWindowThreadProcessId(h, &processID)
		if processID == uint32(pid) {
			hwnd = h
			return 0 // Stop enumeration
		}
		return 1 // Continue enumeration
	}

	windows.EnumWindows(syscall.NewCallback(enumWindowsCallback), nil)

	if hwnd == 0 {
		s.logger.Error("Failed to find window handle for process", "pid", pid)
		return
	}

	// Call manager.Start with the correct arguments, including the HWND
	go s.manager.Start(characterName, true, uint32(pid), uint32(hwnd))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func getRunningProcesses() ([]Process, error) {
	var processes []Process

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, err
	}

	for {
		windowTitle, _ := getWindowTitle(entry.ProcessID)

		if strings.ToLower(syscall.UTF16ToString(entry.ExeFile[:])) == "d2r.exe" {
			processes = append(processes, Process{
				WindowTitle: windowTitle,
				ProcessName: syscall.UTF16ToString(entry.ExeFile[:]),
				PID:         entry.ProcessID,
			})
		}

		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return nil, err
		}
	}

	return processes, nil
}

func getWindowTitle(pid uint32) (string, error) {
	var windowTitle string
	var hwnd windows.HWND

	cb := syscall.NewCallback(func(h win.HWND, param uintptr) uintptr {
		var currentPID uint32
		_ = win.GetWindowThreadProcessId(h, &currentPID)

		if currentPID == pid {
			hwnd = windows.HWND(h)
			return 0 // stop enumeration
		}
		return 1 // continue enumeration
	})

	// Enumerate all windows
	windows.EnumWindows(cb, nil)

	if hwnd == 0 {
		return "", fmt.Errorf("no window found for process ID %d", pid)
	}

	// Get window title
	var title [256]uint16
	_, _, _ = winproc.GetWindowText.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(&title[0])),
		uintptr(len(title)),
	)

	windowTitle = syscall.UTF16ToString(title[:])
	return windowTitle, nil

}

func qualityClass(quality string) string {
	switch quality {
	case "LowQuality":
		return "low-quality"
	case "Normal":
		return "normal-quality"
	case "Superior":
		return "superior-quality"
	case "Magic":
		return "magic-quality"
	case "Set":
		return "set-quality"
	case "Rare":
		return "rare-quality"
	case "Unique":
		return "unique-quality"
	default:
		return "unknown-quality"
	}
}

func statIDToText(id stat.ID) string {
	return stat.StringStats[id]
}

func containss(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func (s *HttpServer) initialData(w http.ResponseWriter, r *http.Request) {
	data := s.getStatusData()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *HttpServer) getStatusData() IndexData {
	status := make(map[string]bot.Stats)
	drops := make(map[string]int)

	for _, supervisorName := range s.manager.AvailableSupervisors() {
		status[supervisorName] = s.manager.Status(supervisorName)
		if s.manager.GetSupervisorStats(supervisorName).Drops != nil {
			drops[supervisorName] = len(s.manager.GetSupervisorStats(supervisorName).Drops)
		} else {
			drops[supervisorName] = 0
		}
	}

	return IndexData{
		Version:   config.Version,
		Status:    status,
		DropCount: drops,
	}
}

func (s *HttpServer) Listen(port int) error {
	s.wsServer = NewWebSocketServer()
	go s.wsServer.Run()
	go s.BroadcastStatus()

	http.HandleFunc("/", s.getRoot)
	http.HandleFunc("/config", s.config)
	http.HandleFunc("/supervisorSettings", s.characterSettings)
	http.HandleFunc("/start", s.startSupervisor)
	http.HandleFunc("/stop", s.stopSupervisor)
	http.HandleFunc("/togglePause", s.togglePause)
	http.HandleFunc("/debug", s.debugHandler)
	http.HandleFunc("/debug-data", s.debugData)
	http.HandleFunc("/drops", s.drops)
	http.HandleFunc("/process-list", s.getProcessList)
	http.HandleFunc("/attach-process", s.attachProcess)
	http.HandleFunc("/ws", s.wsServer.HandleWebSocket)    // Web socket
	http.HandleFunc("/initial-data", s.initialData)       // Web socket data
	http.HandleFunc("/api/reload-config", s.reloadConfig) // New handler

	assets, _ := fs.Sub(assetsFS, "assets")
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))

	s.server = &http.Server{
		Addr: fmt.Sprintf(":%d", port),
	}

	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

func (s *HttpServer) reloadConfig(w http.ResponseWriter, r *http.Request) {
	result := s.manager.ReloadConfig()

	response := struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}{
		Success: result.Success,
		Message: "Config reload completed",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *HttpServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx)
}

func (s *HttpServer) getRoot(w http.ResponseWriter, r *http.Request) {
	if !utils.HasAdminPermission() {
		s.templates.ExecuteTemplate(w, "templates/admin_required.gohtml", nil)
		return
	}

	if config.Koolo.FirstRun {
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}

	s.index(w)
}

func (s *HttpServer) debugData(w http.ResponseWriter, r *http.Request) {
	characterName := r.URL.Query().Get("characterName")
	if characterName == "" {
		http.Error(w, "Character name is required", http.StatusBadRequest)
		return
	}

	// Get a fresh context instead of potentially cached one
	ctx := s.manager.GetContext(characterName)
	if ctx == nil {
		http.Error(w, "Context not found", http.StatusNotFound)
		return
	}

	// Force refresh game data
	ctx.RefreshGameData()

	debugData := DebugDataResponse{
		DebugData: ctx.ContextDebug,
		GameData:  ctx.Data,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	if err := json.NewEncoder(w).Encode(debugData); err != nil {
		s.logger.Error("Failed to encode debug data", "error", err)
		http.Error(w, "Failed to encode debug data", http.StatusInternalServerError)
		return
	}
}

func (s *HttpServer) debugHandler(w http.ResponseWriter, r *http.Request) {
	s.templates.ExecuteTemplate(w, "debug.gohtml", nil)
}

func (s *HttpServer) startSupervisor(w http.ResponseWriter, r *http.Request) {
	supervisorList := s.manager.AvailableSupervisors()
	Supervisor := r.URL.Query().Get("characterName")

	// Get the current auth method for the supervisor we wanna start
	supCfg, currFound := config.Characters[Supervisor]
	if !currFound {
		// There's no config for the current supervisor. THIS SHOULDN'T HAPPEN
		return
	}

	// Prevent launching of other clients while there's a client with TokenAuth still starting
	for _, sup := range supervisorList {

		// If the current don't check against the one we're trying to launch
		if sup == Supervisor {
			continue
		}

		if s.manager.GetSupervisorStats(sup).SupervisorStatus == bot.Starting {

			// Prevent launching if we're using token auth & another client is starting (no matter what auth method)
			if supCfg.AuthMethod == "TokenAuth" {
				return
			}

			// Prevent launching if another client that is using token auth is starting
			sCfg, found := config.Characters[sup]
			if found {
				if sCfg.AuthMethod == "TokenAuth" {
					return
				}
			}
		}
	}

	s.manager.Start(Supervisor, false)
	s.initialData(w, r)
}

func (s *HttpServer) stopSupervisor(w http.ResponseWriter, r *http.Request) {
	s.manager.Stop(r.URL.Query().Get("characterName"))
	s.initialData(w, r)
}

func (s *HttpServer) togglePause(w http.ResponseWriter, r *http.Request) {
	s.manager.TogglePause(r.URL.Query().Get("characterName"))
	s.initialData(w, r)
}

func (s *HttpServer) index(w http.ResponseWriter) {
	status := make(map[string]bot.Stats)
	drops := make(map[string]int)

	for _, supervisorName := range s.manager.AvailableSupervisors() {
		status[supervisorName] = bot.Stats{
			SupervisorStatus: bot.NotStarted,
		}

		status[supervisorName] = s.manager.Status(supervisorName)

		if s.manager.GetSupervisorStats(supervisorName).Drops != nil {
			drops[supervisorName] = len(s.manager.GetSupervisorStats(supervisorName).Drops)
		} else {
			drops[supervisorName] = 0
		}

	}

	s.templates.ExecuteTemplate(w, "index.gohtml", IndexData{
		Version:   config.Version,
		Status:    status,
		DropCount: drops,
	})
}

func (s *HttpServer) drops(w http.ResponseWriter, r *http.Request) {
	sup := r.URL.Query().Get("supervisor")
	cfg, found := config.Characters[sup]
	if !found {
		http.Error(w, "Can't fetch drop data because the configuration "+sup+" wasn't found", http.StatusNotFound)
		return
	}

	var Drops []data.Drop

	if s.manager.GetSupervisorStats(sup).Drops == nil {
		Drops = make([]data.Drop, 0)
	} else {
		Drops = s.manager.GetSupervisorStats(sup).Drops
	}

	s.templates.ExecuteTemplate(w, "drops.gohtml", DropData{
		NumberOfDrops: len(Drops),
		Character:     cfg.CharacterName,
		Drops:         Drops,
	})
}

func (s *HttpServer) config(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			s.templates.ExecuteTemplate(w, "config.gohtml", ConfigData{KooloCfg: config.Koolo, ErrorMessage: "Error parsing form"})
			return
		}

		newConfig := *config.Koolo
		newConfig.FirstRun = false // Disable the welcome assistant
		newConfig.D2RPath = r.Form.Get("d2rpath")
		newConfig.D2LoDPath = r.Form.Get("d2lodpath")
		newConfig.CentralizedPickitPath = r.Form.Get("centralized_pickit_path")
		newConfig.UseCustomSettings = r.Form.Get("use_custom_settings") == "true"
		newConfig.GameWindowArrangement = r.Form.Get("game_window_arrangement") == "true"
		// Debug
		newConfig.Debug.Log = r.Form.Get("debug_log") == "true"
		newConfig.Debug.Screenshots = r.Form.Get("debug_screenshots") == "true"
		// Discord
		newConfig.Discord.Enabled = r.Form.Get("discord_enabled") == "true"
		newConfig.Discord.EnableGameCreatedMessages = r.Form.Has("enable_game_created_messages")
		newConfig.Discord.EnableNewRunMessages = r.Form.Has("enable_new_run_messages")
		newConfig.Discord.EnableRunFinishMessages = r.Form.Has("enable_run_finish_messages")
		newConfig.Discord.EnableDiscordChickenMessages = r.Form.Has("enable_discord_chicken_messages")

		// Discord admins who can use bot commands
		discordAdmins := r.Form.Get("discord_admins")
		cleanedAdmins := strings.Map(func(r rune) rune {
			if (r >= '0' && r <= '9') || r == ',' {
				return r
			}
			return -1
		}, discordAdmins)
		newConfig.Discord.BotAdmins = strings.Split(cleanedAdmins, ",")
		newConfig.Discord.Token = r.Form.Get("discord_token")
		newConfig.Discord.ChannelID = r.Form.Get("discord_channel_id")
		// Telegram
		newConfig.Telegram.Enabled = r.Form.Get("telegram_enabled") == "true"
		newConfig.Telegram.Token = r.Form.Get("telegram_token")
		telegramChatId, err := strconv.ParseInt(r.Form.Get("telegram_chat_id"), 10, 64)
		if err != nil {
			s.templates.ExecuteTemplate(w, "config.gohtml", ConfigData{KooloCfg: &newConfig, ErrorMessage: "Invalid Telegram Chat ID"})
			return
		}
		newConfig.Telegram.ChatID = telegramChatId

		err = config.ValidateAndSaveConfig(newConfig)
		if err != nil {
			s.templates.ExecuteTemplate(w, "config.gohtml", ConfigData{KooloCfg: &newConfig, ErrorMessage: err.Error()})
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	s.templates.ExecuteTemplate(w, "config.gohtml", ConfigData{KooloCfg: config.Koolo, ErrorMessage: ""})
}

func (s *HttpServer) characterSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			s.templates.ExecuteTemplate(w, "character_settings.gohtml", CharacterSettings{
				ErrorMessage: err.Error(),
			})
			return
		}

		supervisorName := r.Form.Get("name")
		cfg, found := config.Characters[supervisorName]
		if !found {
			if err := config.CreateFromTemplate(supervisorName); err != nil {
				s.templates.ExecuteTemplate(w, "character_settings.gohtml", CharacterSettings{
					ErrorMessage: err.Error(),
					Supervisor:   supervisorName,
				})
				return
			}
			cfg = config.Characters["template"]
		}

		// Create new config while preserving runtime data
		newConfig := &config.CharacterCfg{}
		*newConfig = *cfg

		// Process all form fields into new config
		processFormIntoConfig(newConfig, r.Form)

		// Save the config
		if err := config.SaveSupervisorConfig(supervisorName, newConfig); err != nil {
			s.templates.ExecuteTemplate(w, "character_settings.gohtml", CharacterSettings{
				ErrorMessage: err.Error(),
				Supervisor:   supervisorName,
			})
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Handle GET request
	supervisor := r.URL.Query().Get("supervisor")
	cfg := config.Characters["template"]
	if supervisor != "" {
		if foundCfg, found := config.Characters[supervisor]; found {
			cfg = foundCfg
		}
	}

	prepareTemplateData(cfg, supervisor, s.templates, w)
}
func processFormIntoConfig(cfg *config.CharacterCfg, form url.Values) {
	// Core settings
	cfg.MaxGameLength, _ = strconv.Atoi(form.Get("maxGameLength"))
	cfg.CharacterName = form.Get("characterName")
	cfg.CommandLineArgs = form.Get("commandLineArgs")
	cfg.KillD2OnStop = form.Has("kill_d2_process")
	cfg.ClassicMode = form.Has("classic_mode")
	cfg.CloseMiniPanel = form.Has("close_mini_panel")

	// Authentication settings
	cfg.Username = form.Get("username")
	cfg.Password = form.Get("password")
	cfg.Realm = form.Get("realm")
	cfg.AuthMethod = form.Get("authmethod")
	cfg.AuthToken = form.Get("AuthToken")

	// Scheduler settings
	cfg.Scheduler.Enabled = form.Has("schedulerEnabled")
	for day := 0; day < 7; day++ {
		starts := form[fmt.Sprintf("scheduler[%d][start][]", day)]
		ends := form[fmt.Sprintf("scheduler[%d][end][]", day)]
		cfg.Scheduler.Days[day].DayOfWeek = day
		cfg.Scheduler.Days[day].TimeRanges = make([]config.TimeRange, 0)
		for i := 0; i < len(starts); i++ {
			if start, err := time.Parse("15:04", starts[i]); err == nil {
				if end, err := time.Parse("15:04", ends[i]); err == nil {
					cfg.Scheduler.Days[day].TimeRanges = append(cfg.Scheduler.Days[day].TimeRanges, struct {
						Start time.Time "yaml:\"start\""
						End   time.Time "yaml:\"end\""
					}{Start: start, End: end})
				}
			}
		}
	}

	// Health settings
	cfg.Health.HealingPotionAt, _ = strconv.Atoi(form.Get("healingPotionAt"))
	cfg.Health.ManaPotionAt, _ = strconv.Atoi(form.Get("manaPotionAt"))
	cfg.Health.RejuvPotionAtLife, _ = strconv.Atoi(form.Get("rejuvPotionAtLife"))
	cfg.Health.RejuvPotionAtMana, _ = strconv.Atoi(form.Get("rejuvPotionAtMana"))
	cfg.Health.ChickenAt, _ = strconv.Atoi(form.Get("chickenAt"))
	cfg.Character.UseMerc = form.Has("useMerc")
	cfg.Health.MercHealingPotionAt, _ = strconv.Atoi(form.Get("mercHealingPotionAt"))
	cfg.Health.MercRejuvPotionAt, _ = strconv.Atoi(form.Get("mercRejuvPotionAt"))
	cfg.Health.MercChickenAt, _ = strconv.Atoi(form.Get("mercChickenAt"))

	// Character settings
	cfg.Character.Class = form.Get("characterClass")
	cfg.Character.StashToShared = form.Has("characterStashToShared")
	cfg.Character.UseTeleport = form.Has("characterUseTeleport")

	// Class-specific settings
	switch cfg.Character.Class {
	case "berserker":
		cfg.Character.BerserkerBarb.SkipPotionPickupInTravincal = form.Has("barbSkipPotionPickupInTravincal")
		cfg.Character.BerserkerBarb.FindItemSwitch = form.Has("characterFindItemSwitch")
	case "nova":
		if threshold, err := strconv.Atoi(form.Get("novaBossStaticThreshold")); err == nil {
			minThreshold := 65 // Default
			switch cfg.Game.Difficulty {
			case difficulty.Normal:
				minThreshold = 1
			case difficulty.Nightmare:
				minThreshold = 33
			case difficulty.Hell:
				minThreshold = 50
			}
			if threshold >= minThreshold && threshold <= 100 {
				cfg.Character.NovaSorceress.BossStaticThreshold = threshold
			} else {
				cfg.Character.NovaSorceress.BossStaticThreshold = minThreshold
			}
		}
	case "mosaic":
		cfg.Character.MosaicSin.UseTigerStrike = form.Has("mosaicUseTigerStrike")
		cfg.Character.MosaicSin.UseCobraStrike = form.Has("mosaicUseCobraStrike")
		cfg.Character.MosaicSin.UseClawsOfThunder = form.Has("mosaicUseClawsOfThunder")
		cfg.Character.MosaicSin.UseBladesOfIce = form.Has("mosaicUseBladesOfIce")
		cfg.Character.MosaicSin.UseFistsOfFire = form.Has("mosaicUseFistsOfFire")
	}

	// Inventory settings
	for y, row := range cfg.Inventory.InventoryLock {
		for x := range row {
			if form.Has(fmt.Sprintf("inventoryLock[%d][%d]", y, x)) {
				cfg.Inventory.InventoryLock[y][x] = 0
			} else {
				cfg.Inventory.InventoryLock[y][x] = 1
			}
		}
	}
	for x, value := range form["inventoryBeltColumns[]"] {
		cfg.Inventory.BeltColumns[x] = value
	}

	// Game settings
	cfg.Game.CreateLobbyGames = form.Has("createLobbyGames")
	cfg.Game.MinGoldPickupThreshold, _ = strconv.Atoi(form.Get("gameMinGoldPickupThreshold"))
	cfg.UseCentralizedPickit = form.Has("useCentralizedPickit")
	cfg.Game.UseCainIdentify = form.Has("useCainIdentify")
	cfg.Game.Difficulty = difficulty.Difficulty(form.Get("gameDifficulty"))
	cfg.Game.RandomizeRuns = form.Has("gameRandomizeRuns")

	// Parse enabled runs
	var enabledRuns []config.Run
	json.Unmarshal([]byte(form.Get("gameRuns")), &enabledRuns)
	cfg.Game.Runs = enabledRuns

	// Area-specific settings
	cfg.Game.Cows.OpenChests = form.Has("gameCowsOpenChests")
	cfg.Game.Pit.MoveThroughBlackMarsh = form.Has("gamePitMoveThroughBlackMarsh")
	cfg.Game.Pit.OpenChests = form.Has("gamePitOpenChests")
	cfg.Game.Pit.FocusOnElitePacks = form.Has("gamePitFocusOnElitePacks")
	cfg.Game.Pit.OnlyClearLevel2 = form.Has("gamePitOnlyClearLevel2")
	cfg.Game.Andariel.ClearRoom = form.Has("gameAndarielClearRoom")
	cfg.Game.StonyTomb.OpenChests = form.Has("gameStonytombOpenChests")
	cfg.Game.StonyTomb.FocusOnElitePacks = form.Has("gameStonytombFocusOnElitePacks")
	cfg.Game.AncientTunnels.OpenChests = form.Has("gameAncientTunnelsOpenChests")
	cfg.Game.AncientTunnels.FocusOnElitePacks = form.Has("gameAncientTunnelsFocusOnElitePacks")
	cfg.Game.Mausoleum.OpenChests = form.Has("gameMausoleumOpenChests")
	cfg.Game.Mausoleum.FocusOnElitePacks = form.Has("gameMausoleumFocusOnElitePacks")
	cfg.Game.DrifterCavern.OpenChests = form.Has("gameDrifterCavernOpenChests")
	cfg.Game.DrifterCavern.FocusOnElitePacks = form.Has("gameDrifterCavernFocusOnElitePacks")
	cfg.Game.SpiderCavern.OpenChests = form.Has("gameSpiderCavernOpenChests")
	cfg.Game.SpiderCavern.FocusOnElitePacks = form.Has("gameSpiderCavernFocusOnElitePacks")
	cfg.Game.Mephisto.KillCouncilMembers = form.Has("gameMephistoKillCouncilMembers")
	cfg.Game.Mephisto.OpenChests = form.Has("gameMephistoOpenChests")
	cfg.Game.Tristram.ClearPortal = form.Has("gameTristramClearPortal")
	cfg.Game.Tristram.FocusOnElitePacks = form.Has("gameTristramFocusOnElitePacks")
	cfg.Game.Nihlathak.ClearArea = form.Has("gameNihlathakClearArea")
	cfg.Game.Baal.KillBaal = form.Has("gameBaalKillBaal")
	cfg.Game.Baal.DollQuit = form.Has("gameBaalDollQuit")
	cfg.Game.Baal.SoulQuit = form.Has("gameBaalSoulQuit")
	cfg.Game.Baal.ClearFloors = form.Has("gameBaalClearFloors")
	cfg.Game.Baal.OnlyElites = form.Has("gameBaalOnlyElites")
	cfg.Game.Eldritch.KillShenk = form.Has("gameEldritchKillShenk")
	cfg.Game.LowerKurastChest.OpenRacks = form.Has("gameLowerKurastChestOpenRacks")
	cfg.Game.Diablo.StartFromStar = form.Has("gameDiabloStartFromStar")
	cfg.Game.Diablo.KillDiablo = form.Has("gameDiabloKillDiablo")
	cfg.Game.Diablo.FocusOnElitePacks = form.Has("gameDiabloFocusOnElitePacks")
	cfg.Game.Diablo.DisableItemPickupDuringBosses = form.Has("gameDiabloDisableItemPickupDuringBosses")

	if attackDist, err := strconv.Atoi(form.Get("gameDiabloAttackFromDistance")); err == nil {
		if attackDist > 25 {
			attackDist = 25
		}
		cfg.Game.Diablo.AttackFromDistance = attackDist
	}

	// Quest settings
	cfg.Game.Quests.ClearDen = form.Has("gameQuestsClearDen")
	cfg.Game.Quests.RescueCain = form.Has("gameQuestsRescueCain")
	cfg.Game.Quests.RetrieveHammer = form.Has("gameQuestsRetrieveHammer")
	cfg.Game.Quests.KillRadament = form.Has("gameQuestsKillRadament")
	cfg.Game.Quests.GetCube = form.Has("gameQuestsGetCube")
	cfg.Game.Quests.RetrieveBook = form.Has("gameQuestsRetrieveBook")
	cfg.Game.Quests.KillIzual = form.Has("gameQuestsKillIzual")
	cfg.Game.Quests.KillShenk = form.Has("gameQuestsKillShenk")
	cfg.Game.Quests.RescueAnya = form.Has("gameQuestsRescueAnya")
	cfg.Game.Quests.KillAncients = form.Has("gameQuestsKillAncients")

	// Terror Zone settings
	cfg.Game.TerrorZone.FocusOnElitePacks = form.Has("gameTerrorZoneFocusOnElitePacks")
	cfg.Game.TerrorZone.SkipOtherRuns = form.Has("gameTerrorZoneSkipOtherRuns")

	// Process immunities
	cfg.Game.Pindleskin.SkipOnImmunities = []stat.Resist{}
	for _, i := range form["gamePindleskinSkipOnImmunities[]"] {
		cfg.Game.Pindleskin.SkipOnImmunities = append(cfg.Game.Pindleskin.SkipOnImmunities, stat.Resist(i))
	}

	cfg.Game.TerrorZone.SkipOnImmunities = []stat.Resist{}
	for _, i := range form["gameTerrorZoneSkipOnImmunities[]"] {
		cfg.Game.TerrorZone.SkipOnImmunities = append(cfg.Game.TerrorZone.SkipOnImmunities, stat.Resist(i))
	}

	// Process Terror Zone areas
	tzAreas := make([]area.ID, 0)
	for _, a := range form["gameTerrorZoneAreas[]"] {
		if ID, err := strconv.Atoi(a); err == nil {
			tzAreas = append(tzAreas, area.ID(ID))
		}
	}
	cfg.Game.TerrorZone.Areas = tzAreas

	// Gambling settings
	cfg.Gambling.Enabled = form.Has("gamblingEnabled")

	// Cube Recipes settings
	cfg.CubeRecipes.Enabled = form.Has("enableCubeRecipes")
	cfg.CubeRecipes.EnabledRecipes = form["enabledRecipes"]

	// Companion settings
	cfg.Companion.Leader = form.Has("companionLeader")
	cfg.Companion.LeaderName = form.Get("companionLeaderName")
	cfg.Companion.GameNameTemplate = form.Get("companionGameNameTemplate")
	cfg.Companion.GamePassword = form.Get("companionGamePassword")

	// Back to town settings
	cfg.BackToTown.NoHpPotions = form.Has("noHpPotions")
	cfg.BackToTown.NoMpPotions = form.Has("noMpPotions")
	cfg.BackToTown.MercDied = form.Has("mercDied")
	cfg.BackToTown.EquipmentBroken = form.Has("equipmentBroken")
}
func prepareTemplateData(cfg *config.CharacterCfg, supervisor string, templates *template.Template, w http.ResponseWriter) {
	enabledRuns := make([]string, 0)
	for _, run := range cfg.Game.Runs {
		enabledRuns = append(enabledRuns, string(run))
	}

	disabledRuns := make([]string, 0)
	for run := range config.AvailableRuns {
		if !slices.Contains(cfg.Game.Runs, run) {
			disabledRuns = append(disabledRuns, string(run))
		}
	}
	sort.Strings(disabledRuns)

	// Build available terror zones map
	availableTZs := make(map[int]string)
	for _, tz := range area.Areas {
		if tz.CanBeTerrorized() {
			availableTZs[int(tz.ID)] = tz.Name
		}
	}

	// Initialize scheduler days if needed
	if cfg.Scheduler.Days == nil || len(cfg.Scheduler.Days) == 0 {
		cfg.Scheduler.Days = make([]config.Day, 7)
		for i := 0; i < 7; i++ {
			cfg.Scheduler.Days[i] = config.Day{DayOfWeek: i}
		}
	}

	dayNames := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}

	templates.ExecuteTemplate(w, "character_settings.gohtml", CharacterSettings{
		Supervisor:   supervisor,
		Config:       cfg,
		DayNames:     dayNames,
		EnabledRuns:  enabledRuns,
		DisabledRuns: disabledRuns,
		AvailableTZs: availableTZs,
		RecipeList:   config.AvailableRecipes,
	})
}
