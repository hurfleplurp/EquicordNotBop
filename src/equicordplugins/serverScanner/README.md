# Discord Server Scanner – Equicord Plugin

This directory contains a TypeScript/TSX rewrite of the original Python-based Discord Server Scanner, adapted to run as an Equicord-compatible plugin.

## Features

- Registers slash commands (`/info`, `/roles`, `/tchannels`, `/vchannels`, `/access`, `/mid`, `/wbh`, `/help`) so you can run audits directly inside any guild.
- Automatically uses the active client's authentication token; no manual token entry required.
- Adds a settings panel with:
  - Guild selector populated through the Discord REST API
  - Buttons to run each command and view formatted results
  - Download support for the member ID export
- Dynamic Webpack probing keeps the plugin self-contained—no build step is required.

## Installation

1. Build or copy `DiscordServerScanner.tsx` into your Equicord plugin workspace (e.g. `src/plugins/DiscordServerScanner.tsx`).
2. Rebuild or reload Equicord so the new plugin is compiled.
3. Enable the plugin from Equicord's plugin manager.

Once enabled, the slash commands appear automatically. Run them inside a server text channel, or open the plugin panel to trigger commands via the UI.

> **Note:** The plugin relies on Discord's internal REST API. It must run inside the Discord desktop client with Equicord injected so it can obtain the active token and Webpack modules.
