# Security Key Seed Writer

This command-line utility writes a 32-byte seed to a security key for use with [DiceKeys/SoloKeys standard for seeding authenticators](https://github.com/dicekeys/seeding-webauthn).

The executable must be run as administrator, such as by running PowerShell as administrator and issuing the command from within that shell.

It takes one parameter: a hex format 32-byte seed (64 hex characters) optionally preceded by "0x".
