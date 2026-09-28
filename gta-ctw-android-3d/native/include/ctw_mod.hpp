#pragma once
#include <cstdint>

namespace ctw {

enum class CameraMode : std::uint8_t {
    Original = 0,
    ThirdPerson = 1,
    FirstPerson = 2,
};

struct ModConfig {
    CameraMode camera_mode{CameraMode::Original};
    float third_person_distance{6.0f};
    float third_person_height{2.2f};
    float third_person_pitch_deg{-12.0f};
    float first_person_near_clip{0.05f};
    float world_stream_multiplier{2.0f};
    float lod_multiplier{2.0f};
};

struct BuildIdentity {
    const char* libgame_sha256;
    const char* label;
};

bool initialize(const BuildIdentity& build, const ModConfig& config);
void shutdown();

} // namespace ctw
