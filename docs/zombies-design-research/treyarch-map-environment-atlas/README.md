# Treyarch Zombies Environment & Map-Authoring Atlas

Status: research atlas v1  
Research cutoff: 2026-09-21  
Target use: original Zombies-style maps for ZOMBIESSSSSSS PORTABLE / NZP-derived prototyping

## Purpose

This folder turns the official Treyarch Zombies map lineage into reusable **level-design knowledge** rather than a collection of copied maps or ripped assets.

The atlas studies:

- macro layout topology
- room-to-room pacing
- training loops and choke points
- zombie ingress / spawn pressure
- prop families and set-dressing density
- tables, chairs, sofas, desks, trash bins, paintings, columns, cabinets, crates, pipes, consoles, rubble, foliage, vehicles, signage and architectural kits
- visual landmarks and sightline control
- interactive-object placement
- lighting as wayfinding
- vertical transitions
- risk/reward dead ends and pause pockets
- how environment art supports gameplay

It is intended to answer questions such as:

> Should this sofa sit in the middle of the route or on the edge?  
> How wide should the path around a table cluster feel?  
> Where should a painting, trash can, pillar, workbench or perk machine go?  
> How much clutter belongs in a training loop versus a narrative room?  
> How do we make a room visually rich without making zombie movement miserable?

## Research policy

This repository stores **derived design analysis, public-source references and original recommendations only**.

Do not commit:
- proprietary Treyarch/Activision map files
- ripped textures, models, audio, animations or scripts
- leaked/decrypted game packages
- copyrighted map geometry copied vertex-for-vertex

Publicly documented or visually inferred measurements are tagged by confidence.

### Evidence grades

| Grade | Meaning |
|---|---|
| A | Official Call of Duty / Treyarch guide, blog, patch note or published tactical map |
| B | Credited developer/environment/lighting artist portfolio describing production work |
| C | Community map documentation / annotated layout / wiki corroboration |
| D | Visual estimate or design inference; never treat as an exact original measurement |

### Coordinate status

| Tag | Meaning |
|---|---|
| documented_exact | Public source supplies the value |
| derived_reference | Derived from an official/public plan or known tool scale |
| visual_estimate | Estimated from imagery/gameplay |
| project_target | Our own recommended value for original maps |
| unknown | No reliable public measurement |

## Files

- [MAP_CATALOG.md](MAP_CATALOG.md) — complete franchise map corpus and topology notes
- [PER_MAP_NOTES.md](PER_MAP_NOTES.md) — reusable environment observations by map
- [ENVIRONMENT_GRAMMAR.md](ENVIRONMENT_GRAMMAR.md) — common Treyarch-style spatial grammar
- [PROP_PLACEMENT_TAXONOMY.md](PROP_PLACEMENT_TAXONOMY.md) — where and why to place common prop types
- [MEASUREMENT_AND_PLACEMENT_GUIDE.md](MEASUREMENT_AND_PLACEMENT_GUIDE.md) — portable scale/clearance rules
- [SOURCES.md](SOURCES.md) — public research sources and provenance

## Core conclusion

The recurring design pattern is not "fill empty space with props." It is:

**blockout the combat route first → reserve readable movement → establish landmarks and interactables → place large prop masses → add medium story props → add small clutter/decals → light important gameplay objects and route decisions → test zombie/player collision → remove anything that produces accidental snagging.**

The environment should look inhabited or ruined while the playable route remains legible.

## Portable design vocabulary

Use these normalized terms in future map plans:

- **Hub** — area with 3+ meaningful route choices.
- **Connector** — corridor/stair/alley joining larger spaces.
- **Training loop** — loop wide enough to kite a horde with readable escape options.
- **Choke** — intentionally narrow or one-direction pressure area.
- **Pause pocket** — protected-ish edge/alcove for buying/crafting/reading the room.
- **Clutter island** — furniture/prop cluster that shapes flow without fully blocking it.
- **Landmark** — visually dominant structure or prop used for orientation.
- **Ingress** — window, breach, ceiling hole, spawn closet, ground spawn or other enemy entry.
- **Soft gate** — hazard, darkness, verticality or enemy pressure discouraging movement without a locked door.
- **Hard gate** — debris, door, power lock or quest lock.
- **Sightline breaker** — column, vehicle, statue, shelf, partition or other mass used to shorten visibility.
- **Edge dressing** — nonessential props placed outside the primary circulation envelope.

## Fast authoring rule

Every new room should be reviewed in this order:

1. player route
2. zombie route
3. escape route
4. interactive placement
5. large obstacle placement
6. narrative set dressing
7. lighting/readability
8. collision cleanup
9. performance/occlusion
10. horde test

A visually beautiful room that fails steps 1–3 is not finished.
