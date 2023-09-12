#pragma once

#include "Array.hpp"

namespace tls::certificates {
	// TODO: obfuscate values (functions that return encrypted values)
	namespace DigiCertGlobalRootG2 {
		constexpr Array<257> modulus  {0x00, 0xbb, 0x37, 0xcd, 0x34, 0xdc, 0x7b, 0x6b, 0xc9, 0xb2, 0x68, 0x90, 0xad, 0x4a, 0x75, 0xff, 0x46, 0xba, 0x21, 0x0a, 0x08, 0x8d, 0xf5, 0x19, 0x54, 0xc9, 0xfb, 0x88, 0xdb, 0xf3, 0xae, 0xf2, 0x3a, 0x89, 0x91, 0x3c, 0x7a, 0xe6, 0xab, 0x06, 0x1a, 0x6b, 0xcf, 0xac, 0x2d, 0xe8, 0x5e, 0x09, 0x24, 0x44, 0xba, 0x62, 0x9a, 0x7e, 0xd6, 0xa3, 0xa8, 0x7e, 0xe0, 0x54, 0x75, 0x20, 0x05, 0xac, 0x50, 0xb7, 0x9c, 0x63, 0x1a, 0x6c, 0x30, 0xdc, 0xda, 0x1f, 0x19, 0xb1, 0xd7, 0x1e, 0xde, 0xfd, 0xd7, 0xe0, 0xcb, 0x94, 0x83, 0x37, 0xae, 0xec, 0x1f, 0x43, 0x4e, 0xdd, 0x7b, 0x2c, 0xd2, 0xbd, 0x2e, 0xa5, 0x2f, 0xe4, 0xa9, 0xb8, 0xad, 0x3a, 0xd4, 0x99, 0xa4, 0xb6, 0x25, 0xe9, 0x9b, 0x6b, 0x00, 0x60, 0x92, 0x60, 0xff, 0x4f, 0x21, 0x49, 0x18, 0xf7, 0x67, 0x90, 0xab, 0x61, 0x06, 0x9c, 0x8f, 0xf2, 0xba, 0xe9, 0xb4, 0xe9, 0x92, 0x32, 0x6b, 0xb5, 0xf3, 0x57, 0xe8, 0x5d, 0x1b, 0xcd, 0x8c, 0x1d, 0xab, 0x95, 0x04, 0x95, 0x49, 0xf3, 0x35, 0x2d, 0x96, 0xe3, 0x49, 0x6d, 0xdd, 0x77, 0xe3, 0xfb, 0x49, 0x4b, 0xb4, 0xac, 0x55, 0x07, 0xa9, 0x8f, 0x95, 0xb3, 0xb4, 0x23, 0xbb, 0x4c, 0x6d, 0x45, 0xf0, 0xf6, 0xa9, 0xb2, 0x95, 0x30, 0xb4, 0xfd, 0x4c, 0x55, 0x8c, 0x27, 0x4a, 0x57, 0x14, 0x7c, 0x82, 0x9d, 0xcd, 0x73, 0x92, 0xd3, 0x16, 0x4a, 0x06, 0x0c, 0x8c, 0x50, 0xd1, 0x8f, 0x1e, 0x09, 0xbe, 0x17, 0xa1, 0xe6, 0x21, 0xca, 0xfd, 0x83, 0xe5, 0x10, 0xbc, 0x83, 0xa5, 0x0a, 0xc4, 0x67, 0x28, 0xf6, 0x73, 0x14, 0x14, 0x3d, 0x46, 0x76, 0xc3, 0x87, 0x14, 0x89, 0x21, 0x34, 0x4d, 0xaf, 0x0f, 0x45, 0x0c, 0xa6, 0x49, 0xa1, 0xba, 0xbb, 0x9c, 0xc5, 0xb1, 0x33, 0x83, 0x29, 0x85};
		constexpr Array<3>   exponent {0x01, 0x00, 0x01};
	}
	namespace BaltimoreCyberTrustRoot {
		constexpr Array<257> modulus  {0x00, 0xa3, 0x04, 0xbb, 0x22, 0xab, 0x98, 0x3d, 0x57, 0xe8, 0x26, 0x72, 0x9a, 0xb5, 0x79, 0xd4, 0x29, 0xe2, 0xe1, 0xe8, 0x95, 0x80, 0xb1, 0xb0, 0xe3, 0x5b, 0x8e, 0x2b, 0x29, 0x9a, 0x64, 0xdf, 0xa1, 0x5d, 0xed, 0xb0, 0x09, 0x05, 0x6d, 0xdb, 0x28, 0x2e, 0xce, 0x62, 0xa2, 0x62, 0xfe, 0xb4, 0x88, 0xda, 0x12, 0xeb, 0x38, 0xeb, 0x21, 0x9d, 0xc0, 0x41, 0x2b, 0x01, 0x52, 0x7b, 0x88, 0x77, 0xd3, 0x1c, 0x8f, 0xc7, 0xba, 0xb9, 0x88, 0xb5, 0x6a, 0x09, 0xe7, 0x73, 0xe8, 0x11, 0x40, 0xa7, 0xd1, 0xcc, 0xca, 0x62, 0x8d, 0x2d, 0xe5, 0x8f, 0x0b, 0xa6, 0x50, 0xd2, 0xa8, 0x50, 0xc3, 0x28, 0xea, 0xf5, 0xab, 0x25, 0x87, 0x8a, 0x9a, 0x96, 0x1c, 0xa9, 0x67, 0xb8, 0x3f, 0x0c, 0xd5, 0xf7, 0xf9, 0x52, 0x13, 0x2f, 0xc2, 0x1b, 0xd5, 0x70, 0x70, 0xf0, 0x8f, 0xc0, 0x12, 0xca, 0x06, 0xcb, 0x9a, 0xe1, 0xd9, 0xca, 0x33, 0x7a, 0x77, 0xd6, 0xf8, 0xec, 0xb9, 0xf1, 0x68, 0x44, 0x42, 0x48, 0x13, 0xd2, 0xc0, 0xc2, 0xa4, 0xae, 0x5e, 0x60, 0xfe, 0xb6, 0xa6, 0x05, 0xfc, 0xb4, 0xdd, 0x07, 0x59, 0x02, 0xd4, 0x59, 0x18, 0x98, 0x63, 0xf5, 0xa5, 0x63, 0xe0, 0x90, 0x0c, 0x7d, 0x5d, 0xb2, 0x06, 0x7a, 0xf3, 0x85, 0xea, 0xeb, 0xd4, 0x03, 0xae, 0x5e, 0x84, 0x3e, 0x5f, 0xff, 0x15, 0xed, 0x69, 0xbc, 0xf9, 0x39, 0x36, 0x72, 0x75, 0xcf, 0x77, 0x52, 0x4d, 0xf3, 0xc9, 0x90, 0x2c, 0xb9, 0x3d, 0xe5, 0xc9, 0x23, 0x53, 0x3f, 0x1f, 0x24, 0x98, 0x21, 0x5c, 0x07, 0x99, 0x29, 0xbd, 0xc6, 0x3a, 0xec, 0xe7, 0x6e, 0x86, 0x3a, 0x6b, 0x97, 0x74, 0x63, 0x33, 0xbd, 0x68, 0x18, 0x31, 0xf0, 0x78, 0x8d, 0x76, 0xbf, 0xfc, 0x9e, 0x8e, 0x5d, 0x2a, 0x86, 0xa7, 0x4d, 0x90, 0xdc, 0x27, 0x1a, 0x39};
		constexpr Array<3>   exponent {0x01, 0x00, 0x01};
	}
}