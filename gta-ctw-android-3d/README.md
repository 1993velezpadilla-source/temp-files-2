# GTA Chinatown Wars Android 3D Mod

Experimental Android mod project targeting **GTA: Chinatown Wars 4.4.243 arm64**.

## Goals

- Preserve the original Android gameplay/data.
- Add switchable camera modes:
  - Original top-down
  - Third-person
  - First-person
- Port the useful camera behavior from the open-source PSP Fusion Fix without hard-coding PSP addresses.
- Fix player/weapon geometry that disappears or clips when the camera moves below the original top-down envelope.
- Increase usable world visibility by treating draw distance as a pipeline:
  - camera far clip
  - world-sector streaming radius
  - visibility/culling radius
  - LOD thresholds
  - entity/vehicle/ped streaming
- Keep patches version-gated and signature-checked. Never patch an unknown libGame.so.

## Known public reverse-engineering references

- NaGaa95/gtactw_nx — loads the Android 4.4.243 arm64 libGame.so and game assets.
- DK22Pac/CTW-Mobile-Explorer — documented game.pak/resource structures and exporters.
- spicybung/BLeeds — Blender IO for Leeds Engine formats.
- ThirteenAG/WidescreenFixesPack — GTACTW PPSSPP Fusion Fix camera source.

No proprietary game assets are stored in this repository. Supply files from your own installed copy.

## Phase gates

### G0 — ingest
- extract APK
- locate arm64 libGame.so
- locate game.pak / dxt.bin
- generate SHA-256 manifest
- refuse unknown/missing required inputs

### G1 — binary map
- enumerate exported symbols
- identify camera update path
- identify projection/far-clip path
- identify world-sector streaming/culling paths
- record signatures for the exact build

### G2 — camera
- third-person toggle
- pitch / height / distance
- collision-safe near clip
- first-person transform

### G3 — player render
- audit body-part visibility
- disable inappropriate top-down-only hide/cull rules
- verify weapons/hands/body in first/third person

### G4 — distance
- far clip
- sector streaming
- LOD thresholds
- entity streaming
- memory/performance governor

### G5 — Android package
- inject/loader
- signed test APK
- runtime telemetry
- visual capture gates
