package logger

import (
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

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig), // JSON logs
		writer,
		zapcore.InfoLevel,
	)

	Log = zap.New(core, zap.AddCaller())

	zap.ReplaceGlobals(Log)
}
