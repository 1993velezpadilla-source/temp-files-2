# Measurement & Placement Guide

## Important limitation

Public sources do **not** provide a complete authoritative coordinate dump for every official Treyarch Zombies map.

Therefore this atlas never invents exact Treyarch positions.

Use these tags:

- `documented_exact` — a public source publishes the number.
- `derived_reference` — calculated from a public plan/tool scale.
- `visual_estimate` — estimated from screenshots/gameplay.
- `project_target` — our own design recommendation.
- `unknown` — do not guess.

Leaked/ripped proprietary .map files are not required and should not be committed.

## Engine-neutral scale

Define:

- **W** = player collision width/diameter.
- **H** = standing player collision height.
- **S** = comfortable strafe step; default project concept = 0.5W.

Use ratios first, then convert to Quake/NZP or future engine units.

### Project target clearances

These are original design targets, **not official Treyarch measurements**.

| Space | Recommended clear width | Intent |
|---|---:|---|
| single-person emergency gap | 1.25–1.5 W | feels dangerous; use rarely |
| intentional choke | 1.5–2.0 W | pressure point |
| normal connector | 2.0–3.0 W | two-way combat movement |
| primary sprint lane | 3.0–4.0 W | reliable horde traversal |
| loop around large prop | 2.5–4.0 W per important side | readable orbit |
| revive / interaction pocket | about 2.5 W × 2.5 W minimum | player can stop without blocking all flow |
| major horde-training lane | 4.0–6.0 W | supports large horde turns |

### Vertical targets

| Feature | Project target |
|---|---|
| normal clear ceiling | >= 1.25 H |
| dramatic hall ceiling | 1.75–3.0 H |
| low pressure connector | 1.1–1.25 H |
| rail/cover mass | ~0.45–0.65 H |
| table/desk visual mass | ~0.4–0.55 H |
| wall interaction center | ~0.55–0.75 H depending on model |

Do not scale props from these blindly; test against first-person camera and collider.

## Prop collision envelope

### Rule A — visible mass
Player collision should not extend significantly beyond the visible silhouette.

### Rule B — simplify
Complex decorative meshes should use simple box/capsule/hull collision.

Examples:
- table: one top/body hull, not four snagging leg colliders
- chair: one simple low box or no collision if decorative
- car: sealed hull; do not allow player feet under chassis
- rubble pile: one broad ramp/blocker, not 30 colliding stones
- tree: simple trunk capsule; roots visual-only
- shelf: one box
- pipes/cables: usually no collision unless route-defining

### Rule C — remove micro-gaps
If the gap between two colliders is less than about 1.25 W and is not meant to be traversable, close it completely.

A fake traversable gap is worse than a solid wall because players enter it under pressure and get stuck.

## Turn radius

At every 90-degree corner on a main loop:
- keep the inside corner free of tiny props
- keep the outside corner visually open enough to read what follows
- avoid a pillar exactly at the apex

For a large horde-training turn, target at least ~2.5–3 W of effective turn radius around the obstacle.

## Doorways

Doorway sizing is engine/game dependent.

Project rule:
- ordinary combat doorway: >= 2 W clear when it must support two-way movement
- dangerous choke doorway: 1.5–2 W
- grand/landmark doorway: 2.5–4 W
- no trash bin, chair, post, broken beam or decorative collision within the immediate threshold

A community BO3 Radiant/MCP project built for BO3 mod tools documents world coordinates in inches and gives examples including a 64×96 doorway, 16-unit wall thickness and a 512×512×256 zone. Treat those as **tool-reference examples only**, not universal Treyarch map standards.

## Stairs

Stair requirements:
- top and bottom landing = clear
- no small prop within ~1 W of landing center
- visually mark change in elevation
- zombies must be able to path the full width actually shown
- if the staircase is a designed choke, make the danger come from width/ingress, not collision bugs

## Columns

Use a structural grid.

For playable free-standing columns:
- keep >= 2 W between column and nearest hard obstacle for normal circulation
- if < 1.5 W, close the gap or clearly make it non-route
- around a central column island in a training room, reserve >= 2.5 W on the preferred orbit side

## Tables and sofas

### Wall-adjacent
Leave ~0–0.25 W behind the object; do not create a useless sliver gap.

### Free-standing
Reserve:
- >= 2 W on secondary sides
- >= 2.5–3 W on intended horde side

### Furniture cluster
Treat the **cluster** as one obstacle silhouette. Avoid chair-by-chair collision maze behavior.

## Paintings / wall art

No collision.

Project placement method:
1. locate eye/camera horizon;
2. place hero art so center sits near natural viewing zone;
3. use smaller frames around it;
4. avoid competing with wall-buy or interactable silhouette;
5. never place high-frequency wall art on every wall.

## Trash cans / bins

Default: EDGE.

Offset from primary lane so their collider does not reduce route width below target.

If a bin is knocked over:
- prefer no collision or a broad simple hull;
- never let lid/handles become blockers.

## Interactive standing footprint

Every perk/crafting/power/Pap-style interaction should have:
- clear player standing point
- readable escape side
- no zombie spawn directly overlapping that point
- no overlapping prompt from neighboring interactable
- no movable physics junk in footprint

Draw this footprint in graybox as a temporary decal/box and protect it through art passes.

## Spawn / ingress clearance

For each zombie ingress:
- reserve a short AI landing/entry lane
- prevent large art props from intersecting animation/pathing
- keep player-readable silhouette
- do not place interactables directly on the ingress mouth unless deliberately risky

## Clutter budget by zone

Project target, based on **playable floor area** rather than raw prop count:

- primary training area: keep roughly 70–85% of floor visually/physically open
- ordinary combat room: 55–75% open
- tight connector: 70–90% of the actual corridor strip open
- narrative/noncombat edge: can be much denser because clutter sits outside circulation
- inaccessible background: unlimited visual density subject to performance

These are project heuristics, not measured Treyarch percentages.

## Estimating dimensions from reference imagery

When exact coordinates are unavailable:

1. identify a known human-scale object (door, standard stair, character);
2. estimate `W` and `H` ratios rather than meters;
3. map wall-to-wall distance in those ratios;
4. note lens/FOV distortion;
5. cross-check from at least two angles;
6. mark result `visual_estimate`;
7. never convert estimate into a false "official" number.

## Map reconstruction versus original design

For internal study, a rough blockout may follow a reference layout.

For a public original release:
- alter room dimensions
- alter route order/branching
- redesign landmarks
- replace architectural theme
- replace prop compositions
- replace quest/interactable locations
- preserve only abstract gameplay lessons (pressure, loop, rhythm, readability)

The goal is to inherit design intelligence, not copyrighted expression.
