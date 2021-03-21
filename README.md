# Security Key Seed Writer

This command-line utility writes a 32-byte seed to a security key for use with [DiceKeys/SoloKeys standard for seeding authenticators](https://github.com/dicekeys/seeding-webauthn).

The executable must be run as administrator, such as by running PowerShell as administrator and issuing the command from within that shell.

It takes one parameter: a hex format 32-byte seed (64 hex characters) optionally preceded by "0x".  For example, for seed `0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`:

```
SeedSecurityKey.exe 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

 (DO NOT USE THE ABOVE SEED!)


You can download the latest release from the [releases directory](./releases).