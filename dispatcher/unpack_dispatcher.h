#pragma once


unsigned char unpack_dispatcher[] = {
  0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41,
  0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0xe8,
  0x00, 0x00, 0x00, 0x00, 0x5a, 0x48, 0x89, 0xd7, 0x48, 0x81, 0xc7, 0xe3,
  0xaa, 0xff, 0xff, 0x48, 0x83, 0xc2, 0x43, 0x48, 0xc7, 0xc6, 0x0f, 0x00,
  0x00, 0x00, 0x56, 0x48, 0x89, 0xe6, 0x48, 0xc7, 0xc1, 0x1d, 0x00, 0x00,
  0x00, 0xe8, 0x34, 0x05, 0x00, 0x00, 0x5e, 0x41, 0x5f, 0x41, 0x5e, 0x41,
  0x5d, 0x41, 0x5c, 0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x5d,
  0x5f, 0x5e, 0x5a, 0x59, 0x5b, 0x58, 0xe9, 0x2b, 0xf8, 0xff, 0xff
};
unsigned int unpack_dispatcher_len = 95;
