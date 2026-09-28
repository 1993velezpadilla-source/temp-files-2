#include "ctw_mod.hpp"

#include <cstdio>
#include <cstring>

namespace ctw {

static bool g_initialized = false;
static ModConfig g_config{};

static bool is_supported_build(const BuildIdentity& build) {
    // Intentionally fail closed until G1 records the exact Android build hash.
    // No blind offsets, no "close enough" patching.
    return build.libgame_sha256 != nullptr &&
           build.label != nullptr &&
           std::strlen(build.libgame_sha256) == 64 &&
           std::strcmp(build.label, "UNMAPPED") != 0;
}

bool initialize(const BuildIdentity& build, const ModConfig& config) {
    if (g_initialized)
        return true;

    if (!is_supported_build(build)) {
        std::fprintf(stderr,
            "CTW_MOD: unsupported/unmapped libGame.so; refusing to patch\n");
        return false;
    }

    g_config = config;

    // G1 will populate version-specific symbol/signature resolution here.
    // G2: camera update / projection hooks.
    // G3: player-part visibility and near-camera culling.
    // G4: sector streaming, visibility radius and LOD thresholds.

    g_initialized = true;
    std::fprintf(stderr, "CTW_MOD_BOOTSTRAP_GREEN\n");
    return true;
}

void shutdown() {
    g_initialized = false;
}

} // namespace ctw
