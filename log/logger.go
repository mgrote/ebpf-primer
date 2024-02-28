package log

import (
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"
)

var Logger logr.Logger

func init() {
	zerologger := zerolog.New(
		zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.StampMilli, NoColor: false},
	).Level(zerolog.TraceLevel).With().Timestamp().Caller().Logger()
	Logger = zerologr.New(&zerologger)
}
