package main

import (
	"io/ioutil"
	"path/filepath"
	"sync"

	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/mattermost/mattermost-server/v5/plugin"
	"github.com/pkg/errors"
)

// Plugin implements the interface expected by the Mattermost server to communicate between the server and plugin processes.
type Plugin struct {
	plugin.MattermostPlugin

	configurationLock sync.RWMutex

	configuration *configuration

	BotUserID string
}

// OnActivate checks if the configurations is valid and ensures the bot account exists
func (p *Plugin) OnActivate() error {
	config := p.getConfiguration()

	if err := config.IsValid(); err != nil {
		return err
	}
	p.API.RegisterCommand(getCommand())

	BotUserID, err := p.Helpers.EnsureBot(&model.Bot{
		Username:    "shodan",
		DisplayName: "Shodan",
		Description: "Created by the Shodan plugin.",
	})
	if err != nil {
		return errors.Wrap(err, "failed to ensure shodan bot")
	}
	p.BotUserID = BotUserID

	bundlePath, err := p.API.GetBundlePath()
	if err != nil {
		return errors.Wrap(err, "couldn't get bundle path")
	}

	if err = p.API.RegisterCommand(getCommand()); err != nil {
		return errors.WithMessage(err, "OnActivate: failed to register command")
	}

	profileImage, err := ioutil.ReadFile(filepath.Join(bundlePath, "assets", "profile.png"))
	if err != nil {
		return errors.Wrap(err, "couldn't read profile image")
	}

	appErr := p.API.SetProfileImage(BotUserID, profileImage)
	if appErr != nil {
		return errors.Wrap(appErr, "couldn't set profile image")
	}

	return nil
}

func main() {
	plugin.ClientMain(&Plugin{})
}

// Check takes care of error handling
func (p *Plugin) Check(e error) *model.AppError {
	if e != nil {
		return &model.AppError{Message: e.Error()}
	}
	return nil
}
