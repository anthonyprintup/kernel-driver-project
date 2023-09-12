#pragma once

#include <common/Configuration.hpp>

namespace Configuration = GlobalConfiguration::KernelMode;

#include <Code Virtualizer/VirtualizerSDKMacros.h>
#include <Code Virtualizer/VM_FISH_LITE.h>
#include <Code Virtualizer/VM_TIGER_LONDON.h>

#define MUTATE_BEGIN					VIRTUALIZER_MUTATE_ONLY_START
#define MUTATE_END						VIRTUALIZER_MUTATE_ONLY_END

#define VM_SIZE_BEGIN					VIRTUALIZER_FISH_LITE_START		/* size:   70, speed: 95%, complexity:  4% */
#define VM_SIZE_END						VIRTUALIZER_FISH_LITE_END		/* size:   70, speed: 95%, complexity:  4% */
#define VM_SIZE_SPEED_BEGIN				VIRTUALIZER_DOLPHIN_WHITE_START	/* size:  297, speed: 88%, complexity: 19% */
#define VM_SIZE_SPEED_END				VIRTUALIZER_DOLPHIN_WHITE_END	/* size:  297, speed: 88%, complexity: 19% */
#define VM_SIZE_COMPLEXITY_BEGIN		VIRTUALIZER_EAGLE_WHITE_START	/* size:  612, speed:  2%, complexity: 92% */
#define VM_SIZE_COMPLEXITY_END			VIRTUALIZER_EAGLE_WHITE_END		/* size:  612, speed:  2%, complexity: 92% */

#define VM_MINIMUM_BEGIN				VIRTUALIZER_TIGER_WHITE_START	/* size: 1000, speed: 96%, complexity: 15% */
#define VM_MINIMUM_END					VIRTUALIZER_TIGER_WHITE_END		/* size: 1000, speed: 96%, complexity: 15% */
#define VM_MEDIUM_BEGIN					VIRTUALIZER_DOLPHIN_RED_START	/* size: 2060, speed: 74%, complexity: 38% */
#define VM_MEDIUM_END					VIRTUALIZER_DOLPHIN_RED_END		/* size: 2060, speed: 74%, complexity: 38% */
#define VM_MAXIMUM_BEGIN				VIRTUALIZER_EAGLE_BLACK_START	/* size: 1338, speed:  1%, complexity: 96% */
#define VM_MAXIMUM_END					VIRTUALIZER_EAGLE_BLACK_END		/* size: 1338, speed:  1%, complexity: 96% */
