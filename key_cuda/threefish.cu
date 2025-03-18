#include <stdint.h>

// Threefish-1024 Constants
#define BLOCK_SIZE 128  // 128 bytes = 1024 bits
#define ROUNDS 72
#define WORDS 16
#define C240 0x1BD11BDAA9FC1A22

// Correct Threefish-1024 Rotation Constants (Skein 1.3 Table 14)
__constant__ int ROTATION_CONSTANTS[ROUNDS][8] = {
    {55, 43, 37, 40, 16, 22, 38, 12},
    {25, 25, 46, 13, 14, 13, 52, 57},
    {33, 8, 18, 57, 21, 12, 32, 54},
    {34, 43, 25, 60, 44, 9, 59, 34},
    {28, 7, 47, 48, 51, 9, 35, 41},
    {17, 6, 18, 25, 43, 42, 40, 15},
    {58, 7, 32, 45, 19, 18, 2, 56},
    {47, 49, 27, 58, 37, 48, 53, 56},
    {57, 48, 50, 34, 11, 3, 58, 43},
    {34, 24, 34, 43, 55, 1, 22, 19},
    {16, 31, 44, 45, 3, 62, 51, 46},
    {57, 38, 26, 1, 15, 27, 25, 32},
    {22, 41, 53, 36, 31, 60, 20, 27},
    {21, 10, 10, 46, 38, 2, 59, 50},
    {39, 27, 28, 14, 55, 54, 27, 34},
    {56, 44, 24, 56, 30, 52, 41, 37},
    {32, 19, 34, 51, 53, 35, 40, 25},
    {17, 43, 39, 31, 14, 19, 25, 46},
    {58, 47, 51, 55, 8, 56, 43, 47},
    {57, 22, 47, 44, 37, 45, 8, 54},
    {52, 34, 49, 56, 35, 55, 46, 42},
    {55, 32, 14, 13, 57, 21, 12, 32},
    {19, 28, 34, 51, 53, 35, 40, 25},
    {47, 49, 27, 58, 37, 48, 53, 56},
    {38, 2, 59, 50, 21, 10, 10, 46},
    {16, 31, 44, 45, 3, 62, 51, 46},
    {25, 25, 46, 13, 14, 13, 52, 57},
    {58, 7, 32, 45, 19, 18, 2, 56},
    {34, 24, 34, 43, 55, 1, 22, 19},
    {33, 8, 18, 57, 21, 12, 32, 54},
    {56, 44, 24, 56, 30, 52, 41, 37},
    {28, 7, 47, 48, 51, 9, 35, 41},
    {17, 6, 18, 25, 43, 42, 40, 15},
    {57, 48, 50, 34, 11, 3, 58, 43},
    {22, 41, 53, 36, 31, 60, 20, 27},
    {39, 27, 28, 14, 55, 54, 27, 34},
    {52, 34, 49, 56, 35, 55, 46, 42},
    {55, 32, 14, 13, 57, 21, 12, 32},
    {19, 28, 34, 51, 53, 35, 40, 25},
    {47, 49, 27, 58, 37, 48, 53, 56},
    {38, 2, 59, 50, 21, 10, 10, 46},
    {16, 31, 44, 45, 3, 62, 51, 46},
    {25, 25, 46, 13, 14, 13, 52, 57},
    {58, 7, 32, 45, 19, 18, 2, 56},
    {34, 24, 34, 43, 55, 1, 22, 19},
    {33, 8, 18, 57, 21, 12, 32, 54},
    {56, 44, 24, 56, 30, 52, 41, 37},
    {28, 7, 47, 48, 51, 9, 35, 41},
    {17, 6, 18, 25, 43, 42, 40, 15},
    {57, 48, 50, 34, 11, 3, 58, 43},
    {22, 41, 53, 36, 31, 60, 20, 27},
    {39, 27, 28, 14, 55, 54, 27, 34},
    {52, 34, 49, 56, 35, 55, 46, 42},
    {55, 32, 14, 13, 57, 21, 12, 32},
    {19, 28, 34, 51, 53, 35, 40, 25},
    {47, 49, 27, 58, 37, 48, 53, 56},
    {38, 2, 59, 50, 21, 10, 10, 46},
    {16, 31, 44, 45, 3, 62, 51, 46},
    {25, 25, 46, 13, 14, 13, 52, 57},
    {58, 7, 32, 45, 19, 18, 2, 56},
    {34, 24, 34, 43, 55, 1, 22, 19},
    {33, 8, 18, 57, 21, 12, 32, 54},
    {56, 44, 24, 56, 30, 52, 41, 37},
    {28, 7, 47, 48, 51, 9, 35, 41},
    {17, 6, 18, 25, 43, 42, 40, 15},
    {57, 48, 50, 34, 11, 3, 58, 43},
    {22, 41, 53, 36, 31, 60, 20, 27},
    {39, 27, 28, 14, 55, 54, 27, 34},
    {52, 34, 49, 56, 35, 55, 46, 42},
    {55, 32, 14, 13, 57, 21, 12, 32},
    {19, 28, 34, 51, 53, 35, 40, 25},
    {47, 49, 27, 58, 37, 48, 53, 56}
};

extern "C" {// Threefish-1024 Encryption Kernel
__global__ void threefish_encrypt_kernel(uint64_t* blocks, int num_blocks, uint64_t* subkeys, int num_subkeys) {
    int block_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (block_idx >= num_blocks) return;

    uint64_t* block = blocks + block_idx * WORDS; // Each block = 16 uint64_t

    // Perform encryption rounds
    for (int round = 0; round < ROUNDS; ++round) {
        // Add subkey every 4 rounds
        if (round % 4 == 0) {
            int subkey_idx = round / 4;
            for (int i = 0; i < WORDS; i++) {
                block[i] += subkeys[subkey_idx * WORDS + i];
            }
        }

        // Mixing steps
        for (int i = 0; i < 8; i++) {
            int rc = ROTATION_CONSTANTS[round][i];
            uint64_t a = block[i];
            uint64_t b = block[i + 8];
            a += b;
            b = (b << rc) | (b >> (64 - rc));
            b ^= a;
            block[i] = a;
            block[i + 8] = b;
        }

        // Permute words (Threefish-1024 permutation)
        uint64_t temp = block[15];
        for (int i = 15; i > 0; i--) {
            block[i] = block[i - 1];
        }
        block[0] = temp;
    }

    // Add final subkey
    for (int i = 0; i < WORDS; i++) {
        block[i] += subkeys[(ROUNDS / 4) * WORDS + i];
    }
}}

// Threefish-1024 Decryption Kernel
__global__ void threefish_decrypt_kernel(uint64_t* blocks, int num_blocks, uint64_t* subkeys, int num_subkeys) {
    int block_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (block_idx >= num_blocks) return;

    uint64_t* block = blocks + block_idx * WORDS;

    // Perform decryption rounds in reverse order
    for (int round = ROUNDS - 1; round >= 0; --round) {
        // Reverse permutation
        uint64_t temp = block[0];
        for (int i = 0; i < 15; i++) {
            block[i] = block[i + 1];
        }
        block[15] = temp;

        // Inverse mixing steps
        for (int i = 7; i >= 0; --i) {
            int rc = ROTATION_CONSTANTS[round][i];
            uint64_t a = block[i];
            uint64_t b = block[i + 8];
            b ^= a;
            b = (b >> rc) | (b << (64 - rc));
            a -= b;
            block[i] = a;
            block[i + 8] = b;
        }

        // Handle subkeys in reverse order
        if (round % 4 == 0) {
            int s = round / 4;
            for (int i = 0; i < WORDS; ++i) {
                block[i] -= subkeys[s * WORDS + i];
            }
        }
    }
}