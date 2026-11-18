package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/seredavin/claude-proxy/internal/chatgpt"
)

func localChatGPTStore() *chatgpt.Store {
	return chatgpt.NewStore(filepath.Join(filepath.Dir(localConfigFile()), "chatgpt"))
}

func cmdChatGPT(args []string) error {
	if len(args) == 0 || (args[0] != "login" && args[0] != "logout" && args[0] != "models" && args[0] != "import") {
		return fmt.Errorf("использование: claude-proxy chatgpt login|logout|models|import [--profile имя]")
	}
	fs := flag.NewFlagSet("chatgpt "+args[0], flag.ContinueOnError)
	profile := fs.String("profile", "default", "имя профиля ChatGPT")
	storeDir := fs.String("store-dir", "", "каталог профилей ChatGPT")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("неожиданные аргументы для chatgpt %s", args[0])
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store := localChatGPTStore()
	if *storeDir != "" {
		store = chatgpt.NewStore(*storeDir)
	}
	switch args[0] {
	case "import":
		return store.Import(ctx, *profile, os.Stdin)
	case "logout":
		return store.Logout(ctx, *profile)
	case "models":
		models, err := store.Models(ctx, *profile)
		if err != nil {
			return err
		}
		for _, model := range models {
			fmt.Printf("%s\t%s\n", model.Slug, model.DisplayName)
		}
		return nil
	}
	fmt.Fprintln(os.Stderr, "Continue with ChatGPT — подтвердите вход в браузере.")
	if err := store.Login(ctx, *profile, func(u string) error {
		command := "xdg-open"
		if runtime.GOOS == "darwin" {
			command = "open"
		}
		if err := exec.CommandContext(ctx, command, u).Run(); err != nil {
			return fmt.Errorf("не удалось открыть браузер через %s", command)
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Профиль ChatGPT %q готов.\n", *profile)
	return nil
}
