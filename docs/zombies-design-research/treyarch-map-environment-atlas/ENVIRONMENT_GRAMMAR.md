# Environment Grammar — Reusable Treyarch Zombies Patterns

This file extracts reusable spatial rules seen repeatedly across official Treyarch Zombies maps. It is **design grammar**, not copied geometry.

## 1. Macro topology families

### Hub-and-spoke
A recognizable central space feeds several branches that later reconnect or terminate.

Examples:
- Shi No Numa: central building with hut routes.
- Shadows of Evil: Junction feeding themed districts.
- IX: arena/temple system.
- Dead of the Night: Main Hall feeding east, west and north paths.

Use when:
- players need an easy mental map
- branches can have distinct visual identities
- the hub can act as an orientation reset

### Ring / loop
Routes reconnect to create a continuous circulation path.

Use when:
- the map needs reliable horde kiting
- players should have a second escape direction
- a central landmark can remain visible while circling

Avoid a perfect empty circle. Add route-width changes, one or two soft bends, and edge dressing so the loop has rhythm.

### Layered vertical stack
Floors overlap and movement is controlled by stairs, elevators, shafts, ziplines, ladders, drops or teleporters.

Examples:
- Five / Classified
- Die Rise
- Voyage of Despair
- Mauer der Toten
- Reckoning

Verticality should change risk. A vertical transition is strongest when it creates:
- temporary commitment
- reduced lateral escape
- a change in visibility
- a new landmark on arrival

### District / node network
Multiple medium-size zones are separated by dangerous connectors.

Examples:
- TranZit
- Shadows of Evil
- Ashes of the Damned
- Outbreak / Operation Deadbolt at much larger scale

Use when the travel itself should create tension.

### Compressed survival box
Few rooms, highly readable geometry, limited escape options.

Examples:
- Nacht der Untoten
- classic survival submaps
- BO7 Survival subsets

These maps depend much more on exact prop collision, ingress direction and doorway width because there are fewer alternate routes.

## 2. Space rhythm

A strong Zombies route usually alternates:

**open combat space → compression → reveal → open space → pressure connector → reward/pause pocket**

Constant width feels flat. Constant tightness feels unfair. Constant openness removes tension.

### Open spaces
Good places for:
- horde training
- boss encounters
- visible landmarks
- multi-direction spawn pressure
- large interactables

Keep their centers relatively readable. Put dense story clutter at edges or in intentional islands.

### Tight spaces
Good places for:
- risk
- traps
- jump scares / sudden ingress
- path commitment
- strong lighting contrast
- short-range combat

Do not add accidental snags to an already intentional choke.

## 3. Primary circulation envelope

Before dressing a room, draw the route a sprinting player would naturally take under pressure.

Protect that envelope.

Recommended project rule:
- no tiny floor props in the center of a high-speed lane
- no chair legs, trash bags, thin pipes or decorative collision that can trap the player
- if a central obstacle exists, make it visually obvious and large enough to read immediately
- collision should match silhouette; invisible collision should not extend far beyond the visible object

Treyarch maps often look dense because the **edges** carry large amounts of detail while the route remains comparatively legible.

## 4. Clutter hierarchy

Dress in three passes.

### Large mass
Examples:
- sofa
- desk bank
- vehicle
- large crate stack
- machine
- statue
- shelving run
- collapsed wall
- rubble mound

Purpose:
- establish silhouette
- define route
- break long sightlines
- create cover/pressure geometry

### Medium story props
Examples:
- chair group
- filing cabinets
- barrels
- luggage
- laboratory carts
- stacked boxes
- work lights
- tool cabinets

Purpose:
- explain the room
- reinforce era/location
- create secondary composition

### Small detail
Examples:
- bottles
- papers
- cups
- books
- loose cables
- small debris
- decals
- photographs

Purpose:
- close-range richness

Small detail should usually have **no player-blocking collision**.

## 5. Prop density gradient

Use a deliberate gradient:

- **training center:** low density
- **main route edges:** medium density
- **corners/dead space:** medium-high density
- **narrative vignette:** high density
- **interactive footprint:** low density immediately around use point
- **spawn closet / zombie-only space:** visually dense is acceptable if AI collision is controlled

This produces the "busy but playable" look.

## 6. Furniture as flow control

Furniture can either be:
- edge dressing
- a route divider
- a hard obstruction
- a progression gate
- a landmark

Nacht demonstrates the strongest version: a sofa/debris object blocks stair progression. Dead of the Night uses centered furniture such as a billiard table as a room-defining landmark while other rooms use tables/workbenches as interaction anchors.

Rule: if furniture enters the center 50% of a combat room, it needs a gameplay reason.

## 7. Columns and pillars

Columns are useful for:
- rhythm along halls
- framing doorways
- breaking a large room into readable bays
- hiding/revealing threats
- supporting architectural identity

Placement rules:
- align to architectural logic, not random scatter
- do not place a thin column exactly on the apex of a high-speed turn
- avoid creating sub-player-width gaps between column and wall
- in a training room, use columns as broad readable islands with generous circulation on both sides
- light or silhouette important columns if they define navigation

Shangri-La production work explicitly included custom brick/column models and set dressing in its cave/Power Room spaces, showing that columns were part of the authored kit, not an afterthought.

## 8. Wall dressing

Paintings, posters, maps, clocks, signs, chalk drawings and bulletin boards should:
- reinforce era/story
- break large wall surfaces
- label route identity
- guide attention toward doors or interactables
- sit outside collision

Do not evenly wallpaper every wall. Use visual clusters.

For mansion/castle/interior themes:
- pair one hero painting/tapestry with smaller supporting frames
- use furniture below wall art to create a complete vignette
- leave some walls intentionally quiet to preserve hierarchy

## 9. Trash cans / small utility props

Trash bins, mop buckets, stools, buckets, small crates and loose luggage are ideal **edge markers**.

Good locations:
- beside a doorway but outside door swing/circulation
- against structural columns
- under stairs
- beside service counters
- at corridor ends
- near maintenance/service zones

Bad locations:
- inside a sprint apex
- centered in a narrow corridor
- within revive circles
- directly in front of a wall buy/perk/crafting interaction

## 10. Tables / desks / workbenches

Tables are especially useful because they create readable rectangular obstacle islands.

Use them to:
- define a laboratory/work area
- split one large room into two lanes
- anchor quest props
- hold narrative clutter
- create a partial loop

Keep at least one clean side for interaction when the table carries quest content.

A crafting bench should normally live in a **pause pocket**: visible from the route, reachable quickly, but not occupying the lane.

## 11. Zombie ingress grammar

Ingress should create pressure from different vectors without making every room feel random.

Families:
- boarded window
- doorway/breach
- ground emergence
- ceiling drop
- spawn closet
- roof drop
- vent/shaft
- teleporter/portal
- exterior climb

Design rules:
- a safe-looking rear flank becomes unsafe through one or two delayed ingress points
- open areas can support multiple low-commitment ingress points
- tight rooms should use fewer, more readable ingress points
- ingress visuals should explain where enemies are coming from
- do not spawn directly in the player's immediate blind collision space without readable telegraphing

## 12. Interactables as landmarks

Perks, power switches, Pack-a-Punch, Mystery Box locations, crafting tables, traps and quest devices should have a readable footprint.

Use:
- contrasting light
- a clean wall/alcove behind the device
- fewer competing props immediately around it
- a nearby route decision or pause pocket

Tag der Toten developer lighting notes explicitly describe lighting workbenches, important objects and the power switch so players can find them.

## 13. Lighting as navigation

Lighting should answer:
- where did I come from?
- where can I go?
- what can I use?
- what is dangerous?
- what is special?

Useful pattern:
- warm/cool contrast between adjacent route families
- small bright pool on an interaction
- darker connector leading to a brighter reveal
- strong emissive or practical light on a landmark
- event-state lighting changes without destroying navigation

Do not illuminate every prop equally.

## 14. Destruction and rubble

Rubble is strongest when it has one of four jobs:
- hard gate
- soft funnel
- sightline breaker
- story evidence

Avoid "confetti rubble" with collision everywhere.

Make 80–90% of small debris nonblocking; reserve blocking collision for obvious large chunks.

## 15. Vehicles

Vehicles work well as:
- large outdoor clutter islands
- route dividers
- landmarks
- cover/sightline blockers
- traversal systems

Examples range from Nuketown's central vehicles to TranZit's bus and Ashes of the Damned's Ol' Tessie.

Give a vehicle obstacle enough clearance to orbit if it is inside a training space.

## 16. Authoring sequence

1. Graybox room volume.
2. Mark player route and zombie route.
3. Place ingress.
4. Place doors/gates/vertical transitions.
5. Place interactables.
6. Place large landmark mass.
7. Add large prop islands.
8. Add medium set dressing.
9. Add small no-collision clutter.
10. Light routes/interactables.
11. Test solo horde circulation.
12. Test four-player congestion.
13. Test revive access.
14. Remove snagging.
15. Optimize and occlude.

## 17. Failure patterns to reject

- random prop scatter
- identical clutter density everywhere
- tiny collision objects in the lane
- interactables hidden by unrelated props
- decorative columns creating 1-player traps
- all rooms the same width
- every corridor straight and fully visible
- central combat spaces filled to the edges
- dead ends with no reward or intentional risk
- visually gorgeous room with no memorable landmark
- zombie spawns that look disconnected from architecture

The target is **controlled chaos**: rich visual density with intentionally protected gameplay flow.
