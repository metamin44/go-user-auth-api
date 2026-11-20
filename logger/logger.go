package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var Log *zap.Logger

func InitLogger() {
	writer := zapcore.AddSync(&lumberjack.Logger{
		Filename:   "logs/app.log", // log file location
		MaxSize:    10,             // MB
		MaxBackups: 5,
		MaxAge:     28, // days
		Compress:   true,
	})

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.LevelKey = "level"
	encoderConfig.MessageKey = "message"
	encoderConfig.CallerKey = "caller"
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	encoder := zapcore.NewJSONEncoder(encoderConfig) // JSON logs

	fileCore := zapcore.NewCore(encoder, writer, zapcore.InfoLevel)
	// Also write to stdout so container runtimes (docker logs) capture logs.
	stdoutCore := zapcore.NewCore(encoder, zapcore.Lock(os.Stdout), zapcore.InfoLevel)

	core := zapcore.NewTee(fileCore, stdoutCore)

	Log = zap.New(core, zap.AddCaller())

	zap.ReplaceGlobals(Log)
}
