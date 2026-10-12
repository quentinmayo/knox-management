module github.com/quentinmayo/knox-management/integration

go 1.27.0

require (
	github.com/pinterest/knox v0.0.0-20261008214052-61dd58235016
	github.com/quentinmayo/StepDownproxy v0.1.0
	github.com/quentinmayo/knox-management v0.1.0
)

require (
	github.com/gorilla/context v1.1.2 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
)

replace github.com/quentinmayo/StepDownproxy => ../../StepDownproxy

replace github.com/quentinmayo/knox-management => ..
