# Reverse-engineering map

This file records facts taken from public source code so implementation does not rely on guesses.

## Android 4.4.243 layout

The open-source gtactw_nx loader documents these required Android files:
- lib/arm64-v8a/libGame.so
- lib/arm64-v8a/libopenal.so
- assets/game.pak
- assets/dxt.bin
- assets/buttonconfig
- language GXT files
- intro video

Its loader resolves JNI entry points from libGame.so and patches functions by symbol/address at runtime.

## game.pak

CTW-Mobile-Explorer documents:
- 4096-byte resource-block addressing
- model resources (MG signature)
- texture resources
- worldstreamblocks
- worldblock resources
- global textures
- vehicle info
- ped info
- dynamic lights
- radar resources

Important structures already documented publicly include ModelVertex, ModelMaterial,
ModelMatrix, WorldSector, SectorLevel and ModelInstance.

## PSP camera reference

GTACTW.PPSSPP.FusionFix demonstrates:
- alternate 3D camera mode
- camera angle adjustment
- camera Z/height adjustment
- disabling cinematic camera while custom camera is active
- runtime toggle and persisted settings

The PSP absolute addresses must NOT be copied to Android. Only the behavior/state
machine is a reference.

## Next binary-map targets

1. Camera orientation/position update.
2. Perspective projection / near and far clip.
3. Player model component visibility.
4. Frustum/distance culling.
5. World sector request radius.
6. LOD selection thresholds.
7. Ped/vehicle/entity streaming radius.

Every Android patch must be signature/hash-gated.
