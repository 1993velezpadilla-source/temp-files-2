# Prop Placement Taxonomy

Goal: make it possible to look at any available asset and immediately know where it belongs in an original Zombies map.

## Placement classes

Every prop should receive one class:

- **EDGE** — against wall/perimeter; decoration first
- **ISLAND** — free-standing obstacle that shapes circulation
- **ANCHOR** — dominant visual object that defines a room
- **INTERACTIVE** — player uses it
- **GATE** — blocks progression until opened/removed
- **SIGHTLINE** — deliberately limits view
- **INGRESS** — part of zombie entrance language
- **VIGNETTE** — story cluster, usually low gameplay importance
- **BACKGROUND** — outside playable collision
- **HAZARD** — damages/impedes player or enemies

## Furniture

### Sofa / couch
Best roles:
- EDGE in lounge/living room
- ISLAND in a wide lobby
- GATE when explicitly used as debris

Placement:
- along wall with side table/lamp for domestic vignette
- angled 5–20° can make ruins feel natural
- keep center-facing sofas out of narrow corridors
- if used as an island, leave clean orbit routes around both long ends

### Chairs
Best roles:
- VIGNETTE around tables/desks
- EDGE in waiting areas
- BACKGROUND in inaccessible audience spaces

Collision:
- simplified or disabled for loose chairs
- never allow chair legs to become micro-snags

Use asymmetry: one chair pushed back, one fallen, one missing often feels more lived-in than a perfect ring.

### Tables
Best roles:
- ISLAND
- ANCHOR for dining/lab/office
- INTERACTIVE support surface

Placement:
- center only in rooms wide enough to orbit
- one long side can face wall if used as work surface
- leave quest/interact side uncluttered
- group small objects on top in 2–3 clusters rather than uniformly

### Desks
Best roles:
- EDGE or half-ISLAND in offices/labs
- VIGNETTE with chair + papers + lamp
- route divider in large admin areas

Avoid rows that create thin maze slits unless that is the intended pressure pattern.

### Beds
Best roles:
- EDGE in bedroom/barracks/hospital
- VIGNETTE with bedside props
- low sightline blocker

Do not place bed corners on a sprint apex.

### Bookshelves / cabinets
Best roles:
- EDGE
- SIGHTLINE
- hidden-door/quest ANCHOR

Prefer long wall runs or paired shelves framing a doorway. Free-standing shelves need broad bases and obvious collision.

## Wall art

### Paintings / photographs / posters
Best roles:
- VIGNETTE
- landmark reinforcement
- visual breadcrumb

Rules:
- no collision
- cluster by narrative purpose
- use a hero frame plus smaller satellites
- reserve empty wall zones near important interactions
- repeated posters/signage can label a district without text UI

### Bulletin boards / maps
Best roles:
- VIGNETTE
- quest clue surface
- wayfinding

Place near:
- command centers
- labs
- offices
- workshop entrances
- safe-ish pause pockets

## Utility props

### Trash cans / bins
Class: EDGE.

Ideal:
- beside service doors
- near counters
- under stairs
- against pillars
- alley/service-zone corners

Never:
- center of a chase lane
- immediately beside revive/interact footprint

### Barrels / drums
Class: EDGE, ISLAND, VIGNETTE, sometimes HAZARD.

Use 1/2/3-unit clusters with height variation. Large stacks should hug industrial edges unless they intentionally create cover.

### Crates
Class: EDGE / ISLAND / GATE / SIGHTLINE.

Build silhouette in tiers:
- one floor crate
- two-stack
- three-stack with one rotated
- tarp/rope variant
- broken variant

Do not create tiny gaps between crate stacks and walls.

### Sandbags
Class: GATE / EDGE / SIGHTLINE.

Use to communicate defensive history. Their low height makes them good separators without killing visibility.

### Filing cabinets / lockers
Class: EDGE / SIGHTLINE.

Great for office/lab rhythm. Slightly offset or open-door variants add story, but collision should remain simple.

### Tool carts / lab carts
Class: EDGE / VIGNETTE.

Excellent medium-scale props beside work areas. Keep casters/wheels nonblocking.

## Architectural props

### Columns / pillars
Class: structural ANCHOR / SIGHTLINE.

Use on a grid or meaningful structural rhythm.
Never scatter columns randomly.

### Railings
Class: GATE / route boundary.

Keep collision predictable. Avoid decorative protrusions at player shoulder height.

### Pipes / ducts
Usually BACKGROUND/EDGE.

Floor pipes crossing the route should be:
- visually obvious and intentionally stepped over, or
- nonblocking

Ceiling/wall pipes are excellent for leading the eye toward exits.

### Doors / frames
Class: GATE / landmark.

Door frames should be among the most readable silhouettes in the map. Strong trim/color/light helps route memory.

### Stairs
Not decoration. Treat stairs as gameplay geometry.

Keep:
- clean landing zones
- no small props on first/last step
- no surprise column at stair exit
- enough overhead clearance for full-speed movement

## Industrial / lab props

### Consoles
EDGE / INTERACTIVE / ANCHOR.

Bank multiple consoles against walls; use a hero console at a route terminus. Keep usable panels facing the player's approach.

### Machinery
ANCHOR / ISLAND / SIGHTLINE.

Large machines can turn an empty square into a loop. Their collision must be broad/simple, not faithful to every pipe.

### Tanks / vats
ANCHOR / SIGHTLINE.

Good for labs. Pair with overhead pipes, floor drains and light source. Leave at least one wide escape side.

### Workbench / crafting station
INTERACTIVE.

Place in a pause pocket:
- visible from route
- not centered in route
- clear standing zone in front
- light/signage contrast
- no trash props in use footprint

## Domestic / mansion props

### Fireplace
ANCHOR / EDGE.

Excellent orientation landmark. Combine with seating or artwork, but keep one clear route past it.

### Dining table
ANCHOR / ISLAND.

Use only when the room supports a full orbit. Chairs can be partially pushed under to simplify collision.

### Piano
ANCHOR / EDGE/ISLAND.

Strong silhouette, useful for mansion/hotel/ship themes. It can identify a room instantly; don't bury it behind clutter.

### Pool/billiard table
ANCHOR / ISLAND.

Naturally creates a rectangular loop and room identity. Dead of the Night demonstrates the value of a central table as both landmark and quest-adjacent object.

## Exterior props

### Vehicles
ANCHOR / ISLAND / SIGHTLINE.

Use as large clean masses. Keep undercarriage collision sealed so players cannot snag.

### Trees
EDGE / ISLAND / BACKGROUND.

Playable trunks need simple cylindrical collision. Root clutter near training paths should be visual only.

### Rocks
EDGE / GATE / SIGHTLINE.

Create readable rock masses rather than fields of individually blocking stones.

### Fences
GATE / route boundary.

Use breaks/gates as strong route choices. Avoid decorative fence collision extending beyond visible bounds.

### Benches
EDGE.

Excellent on promenade, park, station, cemetery and courtyard edges.

## Debris and destruction

### Rubble pile
GATE / EDGE / SIGHTLINE.

One big readable pile beats twenty colliding fragments.

### Broken beams / boards
GATE / INGRESS / VIGNETTE.

If traversable, collision needs generous clearance. If decorative, disable collision.

### Papers / glass / cans / bottles
VIGNETTE only.

No gameplay collision.

## Interactive machines

Perk, Pack-a-Punch, Mystery Box, Arsenal, GobbleGum, power switch and similar devices:

- reserve a rectangular interaction footprint
- use contrast light
- avoid overlapping zombie ingress with the player's standing point
- give the player at least one direction to back away
- do not place two high-priority interactions so close that prompts compete

## Clutter recipes

### Abandoned office corner
desk + chair + filing cabinet + papers + lamp + wall notice

### Laboratory bay
console + cart + cables + specimen cabinet + overhead light + warning decal

### Ruined domestic corner
sofa + side table + lamp + tilted painting + debris edge

### Industrial service corner
barrels + toolbox + pipe manifold + bin + wall signage

### Castle alcove
bench + torch/sconce + banner/painting + small table + pottery

### Street service edge
trash bin + crates + drain + bollard + sign + small debris decal

Each recipe should occupy dead space or frame the route, not consume the primary circulation envelope.

## Final test

For every prop, ask:

1. What class is it?
2. What gameplay job does it perform?
3. Can a sprinting player read it in peripheral vision?
4. Can a horde flow around it?
5. Does its collision match its visual mass?
6. Would removing it improve gameplay? If yes and it adds no story/wayfinding value, remove it.
