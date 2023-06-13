package logging

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type Logger interface {
	Infof(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})

	Info(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Debug(format string, args ...interface{})
	Error(format string, args ...interface{})
	Fatal(format string, args ...interface{})

	Audit(auditType, operation, status, user, format string, args ...interface{})
}

type StdLogger interface {
	Print(...interface{})
	Println(...interface{})
	Printf(string, ...interface{})
}

type Logging struct {
}

func (l *Logging) Infof(format string, args ...interface{}) {
	fileDetails := l.getFileDetails()
	logrus.WithFields(
		logrus.Fields{
			"caller": fileDetails,
		},
	).Infof(format, args...)
}

func (l *Logging) Debugf(format string, args ...interface{}) {
	fileDetails := l.getFileDetails()
	logrus.WithFields(
		logrus.Fields{
			"caller": fileDetails,
		},
	).Debugf(format, args...)
}

func (l *Logging) Errorf(format string, args ...interface{}) {
	fileDetails := l.getFileDetails()
	logrus.WithFields(
		logrus.Fields{
			"caller": fileDetails,
		},
	).Errorf(format, args...)
}

func (l *Logging) Fatalf(format string, args ...interface{}) {
	fileDetails := l.getFileDetails()
	logrus.WithFields(
		logrus.Fields{
			"caller": fileDetails,
		},
	).Fatalf(format, args...)
}

func (l *Logging) Info(format string, args ...interface{}) {
	if len(args) > 0 {
		format = fmt.Sprintf("%s %v", format, args)
	}
	fileDetails := l.getFileDetails()
	logrus.WithFields(
		logrus.Fields{
			"caller": fileDetails,
		},
	).Info(format)
}

func (l *Logging) Warn(format string, args ...interface{}) {
	if len(args) > 0 {
		format = fmt.Sprintf("%s %v", format, args)
	}
	fileDetails := l.getFileDetails()
	logrus.WithFields(
		logrus.Fields{
			"caller": fileDetails,
		},
	).Warn(format)
}

func (l *Logging) Debug(format string, args ...interface{}) {
	if len(args) > 0 {
		format = fmt.Sprintf("%s %v", format, args)
	}
	fileDetails := l.getFileDetails()
	logrus.WithFields(
		logrus.Fields{
			"caller": fileDetails,
		},
	).Debug(format)
}

func (l *Logging) Error(format string, args ...interface{}) {
	if len(args) > 0 {
		format = fmt.Sprintf("%s %v", format, args)
	}
	fileDetails := l.getFileDetails()
	logrus.WithFields(
		logrus.Fields{
			"caller": fileDetails,
		},
	).Error(format)
}

func (l *Logging) Fatal(format string, args ...interface{}) {
	if len(args) > 0 {
		format = fmt.Sprintf("%s %v", format, args)
	}
	fileDetails := l.getFileDetails()
	logrus.WithFields(
		logrus.Fields{
			"caller": fileDetails,
		},
	).Fatal(format)
}

func (l *Logging) Print(args ...interface{}) {
	fileDetails := l.getFileDetails()
	logrus.WithFields(
		logrus.Fields{
			"caller": fileDetails,
		},
	).Print(args)
}

func (l *Logging) Println(args ...interface{}) {
	fileDetails := l.getFileDetails()
	logrus.WithFields(
		logrus.Fields{
			"caller": fileDetails,
		},
	).Println(args)
}

func (l *Logging) Printf(format string, args ...interface{}) {
	fileDetails := l.getFileDetails()
	logrus.WithFields(
		logrus.Fields{
			"caller": fileDetails,
		},
	).Printf(format, args)
}

func (l *Logging) Audit(auditType, operation, status, user, format string, args ...interface{}) {
	fileDetails := l.getFileDetails()
	logrus.WithFields(
		logrus.Fields{
			"type":      auditType,
			"operation": operation,
			"status":    status,
			"user":      user,
			"caller":    fileDetails,
		},
	).Infof(format, args...)
}

func (*Logging) getFileDetails() string {
	pc, file, line, _ := runtime.Caller(2)
	return fmt.Sprintf("%s:%v:%s", file, line, path.Base(runtime.FuncForPC(pc).Name()))
}

func NewLogger() Logger {
	logrus.SetLevel(getLogLevel())
	// logrus.SetReportCaller(true)
	logrus.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})
	return &Logging{}
}

func getLogLevel() (loglevel logrus.Level) {
	level := os.Getenv("LOG_LEVEL")
	loglevel = logrus.InfoLevel
	switch strings.ToLower(level) {
	case "info", "":
		loglevel = logrus.InfoLevel
	case "debug":
		loglevel = logrus.DebugLevel
	case "error":
		loglevel = logrus.ErrorLevel
	}
	return loglevel
}
