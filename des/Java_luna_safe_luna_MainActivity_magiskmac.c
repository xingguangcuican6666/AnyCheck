
uint Java_luna_safe_luna_MainActivity_magiskmac(void)

{
  int iVar1;
  undefined1 *puVar2;
  undefined8 *puVar3;
  byte bVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  bool bVar9;
  bool bVar10;
  uint uVar11;
  int *piVar12;
  char *pcVar13;
  int *piVar14;
  int iVar15;
  char local_236c;
  byte local_2368;
  byte local_2364;
  byte local_2360;
  byte local_235c;
  byte local_2358;
  uint local_2354;
  uint *local_2350;
  int local_2348;
  char cStack_2344;
  undefined8 local_2340;
  undefined8 local_2338;
  undefined8 local_2330;
  ulong local_2328;
  byte local_2320;
  byte local_231c;
  byte local_2318;
  byte local_2314;
  byte local_2310;
  char local_230c;
  uint *local_2308;
  byte local_22fc;
  byte local_22f8;
  byte local_22f4;
  byte local_22f0;
  uint local_22ec;
  byte local_22e8;
  byte local_22e4;
  byte local_22e0;
  byte local_22dc;
  byte local_22d8;
  byte local_22d4;
  char local_22d0;
  byte local_22cc;
  uint *local_22c8;
  byte local_22c0;
  uint local_22bc;
  uint local_22b8;
  byte local_22b4;
  uint *local_22b0;
  uint local_22a4;
  uint local_22a0;
  byte local_229c;
  uint local_2298;
  int local_2294;
  uint local_2290;
  byte local_228c;
  uint local_2288;
  uint local_2284;
  byte local_2280;
  uint local_227c;
  byte local_2278;
  int local_2274;
  char local_2270;
  byte local_226c;
  byte local_2268;
  char local_2264;
  byte local_2260;
  byte local_225c;
  byte local_2258;
  char local_2254 [16];
  uint local_2244;
  undefined2 local_2240;
  undefined2 local_223e;
  undefined4 local_223c;
  undefined4 local_2238;
  undefined1 local_2234;
  char acStack_244 [92];
  char *local_1e8;
  int local_1dc;
  uint *local_1d8;
  uint local_1d0;
  char local_1c9;
  uint *local_1c8;
  uint *local_1c0;
  char local_1b5;
  uint local_1b4;
  uint *local_1b0;
  uint local_1a4;
  ulong local_1a0;
  uint local_194;
  uint *local_190;
  uint *local_188;
  char *local_180;
  char local_171;
  uint *local_170;
  ushort local_164;
  uint local_160;
  uint local_15c;
  uint local_158;
  byte local_152;
  char local_151;
  char *local_150;
  uint local_144;
  uint local_140;
  uint local_13c;
  uint local_138;
  uint local_134;
  char local_12f;
  char local_12e;
  char local_12d;
  byte local_12c;
  byte local_128;
  byte local_124;
  byte local_120;
  byte local_11c;
  byte local_118;
  char local_114;
  byte local_110;
  byte local_10c;
  byte local_108;
  byte local_104;
  byte local_100;
  byte local_fc;
  byte local_f8;
  char local_f4;
  uint *local_f0;
  byte local_e4;
  byte local_e0;
  uint local_dc;
  byte local_d8;
  byte local_d4;
  byte local_d0;
  byte local_cc;
  byte local_c8;
  byte local_c4;
  char local_c0;
  int local_bc;
  uint *local_b8;
  int local_ac;
  uint *local_a8;
  byte local_a0;
  byte local_9c;
  uint local_98;
  byte local_94;
  byte local_90;
  byte local_8c;
  byte local_88;
  byte local_84;
  char local_80;
  int local_7c;
  byte local_78;
  byte local_74;
  byte local_70;
  byte local_6c;
  
  __android_log_print(3,&DAT_0013f18c,&DAT_00140d90);
  local_1e8 = acStack_244;
  __system_property_get(&DAT_00140dc0,acStack_244);
  local_1dc = atoi(acStack_244);
  piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_00140de0,local_1dc);
  iVar1 = -0x30274e97;
LAB_00123454:
  while (iVar15 = iVar1, iVar1 = iVar15, iVar15 < -0x6e22ac4) {
    if (iVar15 < -0x4fe4bc78) {
      if (iVar15 < -0x64a665d6) {
        if (iVar15 < -0x70fbcb43) {
          if (iVar15 < -0x7a24436d) {
            if (iVar15 < -0x7abf6e41) {
              if (iVar15 == -0x7cfe1991) {
                piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_00140fb0,local_2254,
                                                     local_c0,local_c4,local_c8,local_cc,local_d0,
                                                     local_d4);
                iVar1 = 0xc7d17dd;
              }
              else if (iVar15 == -0x7cb062f6) {
                puVar2 = &DAT_00140d4c;
                if ((local_2258 & 1) == 0) {
                  puVar2 = &DAT_00140d50;
                }
                piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_00141000,local_150,puVar2)
                ;
                iVar1 = -0x26fd2332;
                if (local_12f == '\0') {
                  iVar1 = 0x6344707d;
                }
              }
            }
            else if (iVar15 == -0x7abf6e41) {
              piVar14 = (int *)__errno(piVar12);
              pcVar13 = strerror(*piVar14);
              piVar12 = (int *)__android_log_print(4,&DAT_0013f18c,&DAT_00140e50,pcVar13);
              local_1c9 = *piVar14 == 0xd;
              uVar11 = (x.630 + -1) * x.630;
              bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) != 0;
              iVar1 = 0x9000f0b;
              if (9 < y.631 == bVar9 && (9 < y.631 || bVar9)) {
                iVar1 = -0x1496b534;
              }
            }
            else if (iVar15 == -0x7a424dbc) {
              piVar12 = (int *)__android_log_print(4,&DAT_0013f18c,&DAT_00141080);
              iVar1 = -0x5f9b6934;
            }
          }
          else if (iVar15 < -0x750cfdca) {
            if (iVar15 == -0x7a24436d) {
              local_2270 = (char)local_b8[1];
              bVar7 = *(byte *)((long)local_b8 + 5);
              bVar4 = *(byte *)((long)local_b8 + 7);
              bVar5 = *(byte *)((long)local_b8 + 6);
              bVar6 = *(byte *)((long)local_b8 + 9);
              bVar8 = (byte)local_b8[2];
              local_22a4 = 1;
              goto LAB_0012541c;
            }
            if (iVar15 == -0x7a07d18d) {
              uVar11 = close(local_1d0);
              piVar12 = (int *)(ulong)uVar11;
              iVar1 = -0x7420491b;
            }
          }
          else if (iVar15 == -0x750cfdca) {
            iVar1 = 0x40d1b663;
            if (local_138 != 0) {
              iVar1 = 0x6344707d;
            }
          }
          else if (iVar15 == -0x7420491b) {
            uVar11 = close(local_1d0);
            piVar12 = (int *)(ulong)uVar11;
            uVar11 = (x.630 + -1) * x.630;
            local_12d = (~(uint)local_6c | 0xfffffffe) != 0xffffffff;
            bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) == 0;
            iVar1 = -0x1137e3b6;
            if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
              iVar1 = -0x7a07d18d;
            }
          }
        }
        else if (iVar15 < -0x69ce4073) {
          if (iVar15 < -0x6e9ade92) {
            if (iVar15 == -0x70fbcb43) {
              iVar1 = -0x48145516;
            }
            else if (iVar15 == -0x7072d6c2) {
              local_2354 = 0;
              iVar1 = -0x152ff057;
            }
          }
          else if (iVar15 == -0x6e9ade92) {
            bVar9 = ((x.630 + -1) * x.630 & 1U) == 0;
            iVar1 = -0x5d12b22c;
            if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
              iVar1 = 0x1be07323;
            }
          }
          else if (iVar15 == -0x6bc387b3) {
            piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_00141040);
            uVar11 = (x.630 + -1) * x.630;
            bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) == 0;
            iVar1 = -0x4fe4bc78;
            if (y.631 < 10 == bVar9 && (9 < y.631 || !bVar9)) {
              iVar1 = 0xa621906;
            }
          }
        }
        else if (iVar15 < -0x66d56831) {
          if (iVar15 == -0x69ce4073) {
            bVar7 = 1;
LAB_00125540:
            local_22e8 = bVar7;
            iVar1 = -0x10843507;
          }
          else if (iVar15 == -0x67c122ab) {
            local_22bc = local_98;
            local_22c8 = local_a8;
            iVar1 = 0x1ac2f66f;
            local_22c0 = local_9c;
            local_22d0 = local_c0;
            local_22cc = local_a0;
            local_22d8 = local_c8;
            local_22d4 = local_c4;
            local_22e0 = local_d0;
            local_22dc = local_cc;
            local_22e4 = local_d4;
            if (local_ac != 4) {
              iVar1 = 0x36e5afe8;
            }
          }
        }
        else if (iVar15 == -0x66d56831) {
          local_22ec = local_dc;
          local_2308 = local_f0;
          iVar1 = -0x5f6de3d6;
          local_22f4 = local_e0;
          local_230c = local_f4;
          local_22fc = local_e4;
          local_2314 = local_fc;
          local_2310 = local_f8;
          local_231c = local_104;
          local_2318 = local_100;
          local_2320 = local_108;
          if (local_194 != 0x10) {
            iVar1 = -0x1d586b09;
          }
        }
        else if (iVar15 == -0x65b909ef) {
          local_2294 = 0;
          local_22a0 = local_dc;
          local_22b0 = local_f0;
          goto LAB_00124e3c;
        }
      }
      else if (iVar15 < -0x5f6de3d6) {
        if (iVar15 < -0x6223f4a9) {
          if (iVar15 < -0x63cda853) {
            iVar1 = 0x7ea39b0d;
            if ((iVar15 != -0x64a665d6) && (iVar1 = iVar15, iVar15 == -0x63cf7286)) {
              local_1b0 = local_f0;
              local_1a4 = *local_f0;
              local_1a0 = (ulong)local_1a4;
              iVar1 = -0x60acf27a;
              if (local_1a0 < 0x10) {
                iVar1 = 0x78de642d;
              }
            }
          }
          else if (iVar15 == -0x63cda853) {
            local_227c = (uint)local_c4;
            local_2288 = (uint)local_cc;
            local_2284 = (uint)local_c8;
            local_2290 = (uint)local_d0;
            local_2298 = (uint)local_d4;
            local_22a4 = (uint)local_d8;
            iVar1 = -0x7a24436d;
            local_2270 = local_c0;
            if (local_160 != 10) {
              iVar1 = 0x50545478;
            }
          }
          else if (iVar15 == -0x6346b21f) {
            iVar1 = 0x53485761;
            if (local_151 == '\0') {
              iVar1 = 0x414af292;
            }
          }
        }
        else if (iVar15 < -0x60038e56) {
          iVar1 = 0x47a41395;
          if ((iVar15 != -0x6223f4a9) && (iVar1 = iVar15, iVar15 == -0x60acf27a)) {
            iVar1 = 0x78de642d;
            if (local_1a4 <= local_dc) {
              iVar1 = 0x32913cbf;
            }
          }
        }
        else if (iVar15 == -0x60038e56) {
          piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_001410d0);
          iVar1 = 0x12401467;
        }
        else if (iVar15 == -0x5f9b6934) {
          piVar12 = (int *)__android_log_print(4,&DAT_0013f18c,&DAT_00141080);
          bVar9 = ((x.630 + -1) * x.630 & 1U) == 0;
          iVar1 = -0x69ce4073;
          if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
            iVar1 = -0x7a424dbc;
          }
        }
      }
      else if (iVar15 < -0x5807f996) {
        if (iVar15 < -0x5d12b22c) {
          if (iVar15 == -0x5f6de3d6) {
            local_2338 = 0;
            local_2330 = 0;
            local_2340 = 0;
            local_180 = local_2254;
            local_190 = local_f0;
            local_188 = local_f0 + 4;
            local_2350 = local_f0 + 8;
            local_2348 = (int)local_1a0 + -0x20;
            cStack_2344 = '\0';
            local_2254[0] = '\0';
            local_2254[1] = '\0';
            local_2254[2] = '\0';
            local_2254[3] = '\0';
            local_2254[4] = '\0';
            local_2254[5] = '\0';
            local_2254[6] = '\0';
            local_2254[7] = '\0';
            local_2254[8] = '\0';
            local_2254[9] = '\0';
            local_2254[10] = '\0';
            local_2254[0xb] = '\0';
            local_2254[0xc] = '\0';
            local_2254[0xd] = '\0';
            local_2254[0xe] = '\0';
            local_2254[0xf] = '\0';
            iVar1 = 0x1bfb67d6;
          }
          else if (iVar15 == -0x5ed5372e) {
            local_1c8 = &local_2244;
            local_2244 = 0x20;
            local_2240 = 0x12;
            local_223e = 0x301;
            local_223c = 1;
            local_2238 = 0;
            local_2234 = 0;
            local_1c0 = local_1c8;
            piVar12 = (int *)send(local_1d0,local_1c8,0x20,0);
            iVar1 = -0x6e9ade92;
            if (-1 < (long)piVar12) {
              iVar1 = 0x1fb57c4f;
            }
          }
        }
        else if (iVar15 == -0x5d12b22c) {
          piVar14 = (int *)__errno(piVar12);
          pcVar13 = strerror(*piVar14);
          piVar12 = (int *)__android_log_print(4,&DAT_0013f18c,&DAT_00140ec0,pcVar13);
          local_1b5 = *piVar14 == 0xd;
          bVar9 = ((x.630 + -1) * x.630 & 1U) == 0;
          iVar1 = -0x4cdec1b7;
          if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
            iVar1 = 0x1be07323;
          }
        }
        else if (iVar15 == -0x5a98faa2) {
          iVar1 = 0x2e357434;
        }
      }
      else if (iVar15 < -0x53010bc0) {
        if (iVar15 == -0x5807f996) {
          uVar11 = (x.630 + -1) * x.630 & 1;
          iVar1 = 0x72e717c;
          if (9 < y.631 == uVar11 && (9 < y.631 | uVar11) == 1) {
            iVar1 = 0x3d9b8f16;
          }
        }
        else if (iVar15 == -0x57898e1d) {
          local_7c = local_2274;
          iVar1 = 0x113a8675;
          local_94 = local_228c;
          local_90 = local_2280;
          local_8c = local_2278;
          local_88 = local_226c;
          local_84 = local_2268;
          local_80 = local_2264;
          local_78 = local_2260;
          local_74 = local_225c;
        }
      }
      else if (iVar15 == -0x53010bc0) {
        iVar1 = -0x8272410;
      }
      else if (iVar15 == -0x5117567d) {
        local_22ec = local_98;
        local_2308 = local_a8;
        iVar1 = -0x1d586b09;
        local_22f4 = local_9c;
        local_230c = local_c0;
        local_22fc = local_a0;
        local_2314 = local_c8;
        local_2310 = local_c4;
        local_231c = local_d0;
        local_2318 = local_cc;
        local_2320 = local_d4;
        if (local_ac != 0) {
          iVar1 = 0x36e5afe8;
        }
      }
    }
    else if (iVar15 < -0x2b53e716) {
      if (iVar15 < -0x48145516) {
        if (iVar15 < -0x4d8923b1) {
          if (iVar15 < -0x4f974a3e) {
            bVar7 = local_e4;
            if (iVar15 == -0x4fe4bc78) goto LAB_00125540;
            if (iVar15 == -0x4fd63e22) {
              local_22b8 = (uint)local_12c;
              iVar1 = -0x48145516;
            }
          }
          else if (iVar15 == -0x4f974a3e) {
            iVar1 = 0x1c2fff3f;
          }
          else if (iVar15 == -0x4f11376e) {
            piVar12 = (int *)__android_log_print(4,&DAT_0013f18c,&DAT_00140e80);
            iVar1 = -0x3baae473;
          }
        }
        else if (iVar15 < -0x4b147e10) {
          if (iVar15 == -0x4d8923b1) {
            local_2258 = local_134 == 0;
            iVar1 = -0x7cb062f6;
          }
          else if (iVar15 == -0x4cdec1b7) {
            iVar1 = 0x1d14206;
            if (local_1b5 == '\0') {
              iVar1 = 0x47a41395;
            }
          }
        }
        else if (iVar15 == -0x4b147e10) {
          iVar1 = -0x1776e064;
        }
        else if (iVar15 == -0x4aa6cd6a) {
          local_2258 = 0;
          iVar1 = -0x4d8923b1;
          if (local_138 != 0) {
            iVar1 = -0x7cb062f6;
          }
        }
      }
      else if (iVar15 < -0x317035c4) {
        if (iVar15 < -0x3508da89) {
          if (iVar15 == -0x48145516) {
            local_2354 = local_22b8;
            iVar1 = -0x152ff057;
          }
          else if (iVar15 == -0x3baae473) {
            uVar11 = (x.630 + -1) * x.630;
            bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) != 0;
            iVar1 = 0x2e357434;
            if (9 < y.631 == bVar9 && (9 < y.631 || bVar9)) {
              iVar1 = -0x5a98faa2;
            }
          }
        }
        else if (iVar15 == -0x3508da89) {
          piVar12 = (int *)strncpy(local_2254,(char *)(local_b8 + 1),0xf);
          iVar1 = 0x550ad562;
        }
        else if (iVar15 == -0x342194bd) {
          bVar9 = ((x.630 + -1) * x.630 & 1U) == 0;
          iVar1 = 0x1c2fff3f;
          if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
            iVar1 = -0x4f974a3e;
          }
        }
      }
      else if (iVar15 < -0x2d822a27) {
        if (iVar15 == -0x317035c4) {
          piVar12 = (int *)__android_log_print(4,&DAT_0013f18c,&DAT_00140e80);
          iVar1 = 0x4297d5fe;
        }
        else if (iVar15 == -0x30274e97) {
          iVar1 = -0x1a4e27d0;
          if (0x1d < local_1dc) {
            iVar1 = -0xf7c6ed3;
          }
        }
      }
      else if (iVar15 == -0x2d822a27) {
        iVar1 = -0x342194bd;
        if (*(short *)((long)local_188 + 2) != 1) {
          iVar1 = 0x414af292;
        }
      }
      else if (iVar15 == -0x2bee6795) {
        __android_log_print(4,&DAT_0013f18c,&DAT_00140f20);
        piVar12 = (int *)__errno();
        iVar1 = -0x5807f996;
        if (*piVar12 != 0xd) {
          iVar1 = 0x7ea39b0d;
        }
      }
    }
    else if (iVar15 < -0x1776e064) {
      if (iVar15 < -0x26fd2332) {
        if (iVar15 < -0x2ac308d7) {
          if (iVar15 == -0x2b53e716) {
            uVar11 = (x.630 + -1) * x.630 & 1;
            iVar1 = 0x36f9bb62;
            if (9 < y.631 == uVar11 && (9 < y.631 | uVar11) == 1) {
              iVar1 = -0x17d3ed5;
            }
            local_15c = (uint)*(ushort *)((long)local_b8 + 2);
          }
          else if (iVar15 == -0x2b28531b) {
            local_22c8 = local_1c0;
            local_22bc = local_1b4;
            iVar1 = 0x1ac2f66f;
            local_22c0 = local_10c;
            local_22d0 = local_114;
            local_22cc = local_110;
            local_22d8 = local_11c;
            local_22d4 = local_118;
            local_22e0 = local_124;
            local_22dc = local_120;
            local_22e4 = local_128;
          }
        }
        else if (iVar15 == -0x2ac308d7) {
          iVar1 = 0x15808d67;
          if (local_152 == 0) {
            iVar1 = 0x67922579;
          }
        }
        else if (iVar15 == -0x28b50b79) {
          iVar1 = 0x79a8331c;
          if (local_171 == '\0') {
            iVar1 = -0x261f274;
          }
        }
      }
      else if (iVar15 < -0x1d586b09) {
        if (iVar15 == -0x26fd2332) {
          iVar1 = 0x60bad7e7;
          if (local_144 != 0) {
            iVar1 = 0x6344707d;
          }
        }
        else if (iVar15 == -0x258af551) {
          local_2258 = 0;
          iVar1 = 0x4e9bdf36;
          if (local_12f == '\0') {
            iVar1 = -0x7cb062f6;
          }
        }
      }
      else if (iVar15 == -0x1d586b09) {
        uVar11 = (*local_2308 + 3 ^ 3) & *local_2308 + 3;
        local_22bc = local_22ec - uVar11;
        local_22c8 = (uint *)((long)local_2308 + (ulong)uVar11);
        iVar1 = 0x1ac2f66f;
        local_22c0 = local_22f4;
        local_22d0 = local_230c;
        local_22cc = local_22fc;
        local_22d8 = local_2314;
        local_22d4 = local_2310;
        local_22e0 = local_231c;
        local_22dc = local_2318;
        local_22e4 = local_2320;
      }
      else if (iVar15 == -0x1a4e27d0) {
        uVar11 = (x.630 + -1) * x.630;
        bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) == 0;
        iVar1 = 0x24f2504;
        if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
          iVar1 = 0x4f698b08;
        }
      }
    }
    else if (iVar15 < -0x10843507) {
      if (iVar15 < -0x1496b534) {
        if (iVar15 == -0x1776e064) {
          local_12e = local_134 == 0;
          bVar9 = ((x.630 + -1) * x.630 & 1U) == 0;
          iVar1 = 0x369c167;
          if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
            iVar1 = -0x4b147e10;
          }
        }
        else if (iVar15 == -0x152ff057) {
          return local_2354;
        }
      }
      else if (iVar15 == -0x1496b534) {
        piVar12 = (int *)__errno(piVar12);
        pcVar13 = strerror(*piVar12);
        piVar12 = (int *)__android_log_print(4,&DAT_0013f18c,&DAT_00140e50,pcVar13);
        iVar1 = -0x7abf6e41;
      }
      else if (iVar15 == -0x1137e3b6) {
        iVar1 = 0x12401467;
        if (local_12d == '\0') {
          iVar1 = -0x60038e56;
        }
      }
    }
    else if (iVar15 < -0xdaa4e5c) {
      if (iVar15 == -0x10843507) {
        local_22b0 = local_f0;
        local_22a0 = local_dc;
        local_229c = 1;
        local_2294 = 6;
        iVar1 = 0xa95f2e4;
        local_22b4 = local_22e8;
      }
      else if (iVar15 == -0xf7c6ed3) {
        local_1d8 = &local_2244;
        local_1d0 = socket(0x10,3,0);
        piVar12 = (int *)(ulong)local_1d0;
        iVar1 = 0x72392436;
        if (-1 < (int)local_1d0) {
          iVar1 = -0x5ed5372e;
        }
      }
    }
    else if (iVar15 == -0xdaa4e5c) {
      local_2328 = (ulong)CONCAT14(local_74,(uint)local_78);
      iVar1 = 0x70a1b421;
      local_2358 = local_94;
      local_235c = local_90;
      local_2360 = local_8c;
      local_2364 = local_88;
      local_2368 = local_84;
      local_236c = local_80;
      if (local_7c != 0) {
        iVar1 = -0x70fbcb43;
      }
    }
    else if (iVar15 == -0x8272410) {
      local_158 = local_188[2];
      uVar11 = (x.630 + -1) * x.630;
      bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) == 0;
      local_152 = (byte)(local_158 >> 3) & 1;
      iVar1 = -0x2ac308d7;
      if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
        iVar1 = -0x53010bc0;
      }
    }
  }
  if (iVar15 < 0x36f9bb62) {
    if (iVar15 < 0x12401467) {
      if (iVar15 < 0x257d0e8) {
        if (iVar15 < -0x17d3ed5) {
          if (iVar15 < -0x261f274) {
            if (iVar15 == -0x6e22ac4) {
              iVar1 = -0x750cfdca;
              if (local_13c != 0) {
                iVar1 = 0x6344707d;
              }
            }
            else if (iVar15 == -0x6b3bcb5) {
              iVar1 = -0x5117567d;
              if (3 < local_ac) {
                iVar1 = -0x67c122ab;
              }
            }
          }
          else if (iVar15 == -0x261f274) {
            uVar11 = (x.630 + -1) * x.630 & 1;
            iVar1 = -0x8272410;
            if (9 < y.631 == uVar11 && (9 < y.631 | uVar11) == 1) {
              iVar1 = -0x53010bc0;
            }
          }
          else if (iVar15 == -0x1f68aec) {
            local_160 = (uint)local_164;
            iVar1 = -0x261f274;
            if ((int)local_160 <= local_bc) {
              iVar1 = 0x300b6c27;
            }
          }
        }
        else if (iVar15 < 0x1d14206) {
          if (iVar15 == -0x17d3ed5) {
            iVar1 = -0x2b53e716;
          }
          else if (iVar15 == 0x56d0d) {
            iVar1 = -0x2bee6795;
            if (local_194 != 2) {
              iVar1 = -0x66d56831;
            }
          }
        }
        else if (iVar15 == 0x1d14206) {
          bVar9 = ((x.630 + -1) * x.630 & 1U) == 0;
          iVar1 = 0x4297d5fe;
          if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
            iVar1 = -0x317035c4;
          }
        }
        else if (iVar15 == 0x24f2504) {
          piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_00140e10);
          uVar11 = (x.630 + -1) * x.630;
          bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) != 0;
          iVar1 = -0x7072d6c2;
          if (9 < y.631 == bVar9 && (9 < y.631 || bVar9)) {
            iVar1 = 0x4f698b08;
          }
        }
      }
      else if (iVar15 < 0xa621906) {
        if (iVar15 < 0x72e717c) {
          if (iVar15 == 0x257d0e8) {
            uVar11 = (x.630 + -1) * x.630 & 1;
            iVar1 = -0x6bc387b3;
            if (9 < y.631 == uVar11 && (9 < y.631 | uVar11) == 1) {
              iVar1 = 0xa621906;
            }
          }
          else if (iVar15 == 0x369c167) {
            iVar1 = 0x257d0e8;
            if (local_12e == '\0') {
              iVar1 = 0x6344707d;
            }
          }
        }
        else if (iVar15 == 0x72e717c) {
          piVar12 = (int *)__android_log_print(4,&DAT_0013f18c,&DAT_00140e80);
          uVar11 = (x.630 + -1) * x.630 & 1;
          iVar1 = -0x64a665d6;
          if (y.631 < 10 == (uVar11 == 0) && (9 < y.631 | uVar11) == 1) {
            iVar1 = 0x3d9b8f16;
          }
        }
        else if (iVar15 == 0x9000f0b) {
          iVar1 = -0x4f11376e;
          if (local_1c9 == '\0') {
            iVar1 = -0x3baae473;
          }
        }
      }
      else if (iVar15 < 0xc7d17dd) {
        if (iVar15 == 0xa621906) {
          piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_00141040);
          iVar1 = -0x6bc387b3;
        }
        else if (iVar15 == 0xa95f2e4) {
          local_ac = local_2294;
          local_a8 = local_22b0;
          local_98 = local_22a0;
          iVar1 = -0x6b3bcb5;
          local_a0 = local_22b4;
          local_9c = local_229c;
        }
      }
      else if (iVar15 == 0xc7d17dd) {
        local_150 = local_2254;
        bVar9 = local_c0 == '\0';
        local_144 = (uint)local_c4;
        local_140 = (uint)local_c8;
        local_13c = (uint)local_cc;
        local_138 = (uint)local_d0;
        local_134 = (uint)local_d4;
        piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_00140fb0,local_150,local_c0,
                                             local_144,local_140,local_13c,local_138,local_134);
        bVar10 = ((x.630 + -1) * x.630 & 1U) == 0;
        iVar1 = -0x258af551;
        local_12f = bVar9;
        if ((y.631 >= 10 || !bVar10) && y.631 < 10 == bVar10) {
          iVar1 = -0x7cfe1991;
        }
      }
      else if (iVar15 == 0x113a8675) {
        iVar1 = -0xdaa4e5c;
        local_22f0 = local_74;
        local_22f8 = local_78;
        if (5 < local_7c) {
          iVar1 = 0x4e1cd785;
        }
      }
    }
    else if (iVar15 < 0x1dc43ad4) {
      if (iVar15 < 0x1ac2f66f) {
        if (iVar15 < 0x1795e1ae) {
          if (iVar15 == 0x12401467) {
            bVar9 = ((x.630 + -1) * x.630 & 1U) == 0;
            iVar1 = 0x1795e1ae;
            if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
              iVar1 = 0x683a4786;
            }
          }
          else if (iVar15 == 0x15808d67) {
            piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_00140f50,local_2254);
            local_2294 = 4;
            uVar11 = *local_1b0 + 3 & 0xfffffffc;
            local_22a0 = local_dc - uVar11;
            local_22b0 = (uint *)((long)local_190 + (ulong)uVar11);
            iVar1 = 0xa95f2e4;
            local_22b4 = local_e4;
            local_229c = local_e0;
          }
        }
        else if (iVar15 == 0x1795e1ae) {
          bVar7 = ~(byte)(~(uint)local_70 | 0xfffffffe);
          puVar3 = &DAT_00141170;
          if ((~(uint)local_70 | 0xfffffffe) != 0xffffffff) {
            puVar3 = &DAT_00141160;
          }
          piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_00141120,puVar3);
          bVar9 = ((x.630 + -1) * x.630 & 1U) == 0;
          iVar1 = -0x4fd63e22;
          local_12c = bVar7;
          if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
            iVar1 = 0x683a4786;
          }
        }
        else if (iVar15 == 0x197d3929) {
          local_2258 = 0;
          iVar1 = 0x410f03cd;
          if (local_140 != 0) {
            iVar1 = -0x7cb062f6;
          }
        }
      }
      else if (iVar15 < 0x1bfb67d6) {
        if (iVar15 == 0x1ac2f66f) {
          local_f0 = local_22c8;
          local_dc = local_22bc;
          iVar1 = -0x63cf7286;
          local_108 = local_22e4;
          local_104 = local_22e0;
          local_100 = local_22dc;
          local_fc = local_22d8;
          local_f8 = local_22d4;
          local_f4 = local_22d0;
          local_e4 = local_22cc;
          local_e0 = local_22c0;
          if ((int)local_22bc < 0x10) {
            iVar1 = 0x78de642d;
          }
        }
        else if (iVar15 == 0x1be07323) {
          piVar12 = (int *)__errno(piVar12);
          pcVar13 = strerror(*piVar12);
          piVar12 = (int *)__android_log_print(4,&DAT_0013f18c,&DAT_00140ec0,pcVar13);
          iVar1 = -0x5d12b22c;
        }
      }
      else if (iVar15 == 0x1bfb67d6) {
        local_d8 = (byte)((ulong)local_2330 >> 0x20);
        local_d4 = (byte)local_2330;
        local_d0 = (byte)((ulong)local_2338 >> 0x20);
        local_cc = (byte)local_2338;
        local_c8 = (byte)((ulong)local_2340 >> 0x20);
        local_c4 = (byte)local_2340;
        local_bc = local_2348;
        uVar11 = (x.630 + -1) * x.630 & 1;
        iVar1 = 0x34193ae5;
        if (9 < y.631 == uVar11 && (9 < y.631 | uVar11) == 1) {
          iVar1 = 0x707c4682;
        }
        local_b8 = local_2350;
        local_c0 = cStack_2344;
      }
      else if (iVar15 == 0x1c2fff3f) {
        uVar11 = (x.630 + -1) * x.630;
        local_151 = ((local_d8 ^ 0xfe) & local_d8) != 0;
        bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) == 0;
        iVar1 = -0x6346b21f;
        if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
          iVar1 = -0x4f974a3e;
        }
      }
    }
    else if (iVar15 < 0x300b6c27) {
      if (iVar15 < 0x2312ff12) {
        if (iVar15 == 0x1dc43ad4) {
          bVar9 = ((x.630 + -1) * x.630 & 1U) == 0;
          iVar1 = -0x65b909ef;
          if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
            iVar1 = 0x725bdf8c;
          }
        }
        else if (iVar15 == 0x1fb57c4f) {
          piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_00140ef0);
          local_2328 = 0;
          iVar1 = 0x70a1b421;
        }
      }
      else if (iVar15 == 0x2312ff12) {
LAB_00125048:
        local_22a4 = (uint)local_d8;
        bVar6 = local_d4;
        bVar8 = local_d0;
        bVar4 = local_cc;
        bVar5 = local_c8;
        bVar7 = local_c4;
        local_2270 = local_c0;
LAB_0012541c:
        local_227c = (uint)bVar7;
        local_2284 = (uint)bVar5;
        local_2288 = (uint)bVar4;
        local_2290 = (uint)bVar8;
        local_2298 = (uint)bVar6;
        iVar1 = 0x50545478;
      }
      else if (iVar15 == 0x2e357434) {
        bVar9 = ((x.630 + -1) * x.630 & 1U) == 0;
        iVar1 = 0x5256d6fc;
        if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
          iVar1 = -0x5a98faa2;
        }
      }
    }
    else if (iVar15 < 0x34193ae5) {
      if (iVar15 == 0x300b6c27) {
        uVar11 = (x.630 + -1) * x.630;
        bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) == 0;
        iVar1 = -0x2b53e716;
        if (y.631 < 10 == bVar9 && (9 < y.631 || !bVar9)) {
          iVar1 = -0x17d3ed5;
        }
      }
      else if (iVar15 == 0x32913cbf) {
        local_194 = (uint)(ushort)local_f0[1];
        iVar1 = 0x460d9d66;
        if (local_194 != 3) {
          iVar1 = 0x56d0d;
        }
      }
    }
    else if (iVar15 == 0x34193ae5) {
      uVar11 = (x.630 + -1) * x.630;
      local_171 = 3 < local_bc;
      bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) == 0;
      iVar1 = -0x28b50b79;
      if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
        iVar1 = 0x707c4682;
      }
    }
    else if (iVar15 == 0x36e5afe8) {
      local_2274 = local_ac;
      local_228c = local_d4;
      local_2280 = local_d0;
      local_2278 = local_cc;
      local_226c = local_c8;
      local_2268 = local_c4;
      local_2264 = local_c0;
      local_2260 = local_a0;
      local_225c = local_9c;
LAB_00124fb0:
      iVar1 = -0x57898e1d;
    }
    goto LAB_00123454;
  }
  if (iVar15 < 0x5256d6fc) {
    if (iVar15 < 0x460d9d66) {
      if (iVar15 < 0x410f03cd) {
        if (iVar15 < 0x3d9b8f16) {
          if (iVar15 == 0x36f9bb62) {
            iVar1 = 0x46ab3853;
          }
          else if (iVar15 == 0x389352ad) {
            piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_00140f80,local_2254);
            local_2294 = 4;
            uVar11 = *local_1b0 + 3 & 0xfffffffc;
            local_22a0 = local_dc - uVar11;
            local_22b0 = (uint *)((long)local_190 + (ulong)uVar11);
LAB_00124e3c:
            iVar1 = 0xa95f2e4;
            local_22b4 = local_e4;
            local_229c = local_e0;
          }
        }
        else if (iVar15 == 0x3d9b8f16) {
          piVar12 = (int *)__android_log_print(4,&DAT_0013f18c,&DAT_00140e80);
          iVar1 = 0x72e717c;
        }
        else if (iVar15 == 0x40d1b663) {
          uVar11 = (x.630 + -1) * x.630;
          bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) != 0;
          iVar1 = -0x1776e064;
          if (9 < y.631 == bVar9 && (9 < y.631 || bVar9)) {
            iVar1 = -0x4b147e10;
          }
        }
      }
      else if (iVar15 < 0x41da1a33) {
        if (iVar15 == 0x410f03cd) {
          local_2258 = 0;
          iVar1 = -0x4aa6cd6a;
          if (local_13c != 0) {
            iVar1 = -0x7cb062f6;
          }
        }
        else if (iVar15 == 0x414af292) {
          uVar11 = (x.630 + -1) * x.630;
          bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) == 0;
          iVar1 = 0x1dc43ad4;
          if (y.631 < 10 == bVar9 && (9 < y.631 || !bVar9)) {
            iVar1 = 0x725bdf8c;
          }
        }
      }
      else if (iVar15 == 0x41da1a33) {
        uVar11 = (x.630 + -1) * x.630 & 1;
        iVar1 = 0x550ad562;
        if (9 < y.631 == uVar11 && (9 < y.631 | uVar11) == 1) {
          iVar1 = -0x3508da89;
        }
      }
      else if (iVar15 == 0x4297d5fe) {
        piVar12 = (int *)__android_log_print(4,&DAT_0013f18c,&DAT_00140e80);
        bVar9 = ((x.630 + -1) * x.630 & 1U) == 0;
        iVar1 = -0x6223f4a9;
        if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
          iVar1 = -0x317035c4;
        }
      }
      goto LAB_00123454;
    }
    if (0x4e1cd784 < iVar15) {
      if (iVar15 < 0x4f698b08) {
        if (iVar15 == 0x4e1cd785) {
          uVar11 = (x.630 + -1) * x.630;
          bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) != 0;
          iVar1 = -0x7420491b;
          local_70 = local_22f8;
          local_6c = local_22f0;
          if (9 < y.631 == bVar9 && (9 < y.631 || bVar9)) {
            iVar1 = -0x7a07d18d;
          }
        }
        else if (iVar15 == 0x4e9bdf36) {
          local_2258 = 0;
          iVar1 = 0x197d3929;
          if (local_144 != 0) {
            iVar1 = -0x7cb062f6;
          }
        }
      }
      else if (iVar15 == 0x4f698b08) {
        piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_00140e10);
        iVar1 = 0x24f2504;
      }
      else if (iVar15 == 0x50545478) {
        local_2330 = CONCAT44(local_22a4,local_2298);
        local_2338 = CONCAT44(local_2290,local_2288);
        uVar11 = (ushort)*local_170 + 3 & 0x1fffc;
        local_2340 = CONCAT44(local_2284,local_227c);
        local_2348 = local_bc - uVar11;
        local_2350 = (uint *)((long)local_b8 + (ulong)uVar11);
        iVar1 = 0x1bfb67d6;
        cStack_2344 = local_2270;
      }
      goto LAB_00123454;
    }
    if (iVar15 < 0x47a41395) {
      if (iVar15 == 0x460d9d66) goto LAB_00123404;
      if (iVar15 == 0x46ab3853) {
        iVar1 = 0x6160ed10;
        if (2 < (int)local_15c) {
          iVar1 = 0x7671f0ea;
        }
      }
      goto LAB_00123454;
    }
    if (iVar15 != 0x47a41395) {
      if (iVar15 == 0x4aa0451c) goto LAB_00125048;
      goto LAB_00123454;
    }
    uVar11 = close(local_1d0);
    piVar12 = (int *)(ulong)uVar11;
  }
  else {
    if (0x707c4681 < iVar15) {
      if (iVar15 < 0x7671f0ea) {
        if (iVar15 < 0x72392436) {
          if (iVar15 == 0x707c4682) {
            iVar1 = 0x34193ae5;
          }
          else if (iVar15 == 0x70a1b421) {
            local_110 = (byte)local_2328;
            local_10c = (byte)(local_2328 >> 0x20);
            local_128 = local_2358;
            local_124 = local_235c;
            local_120 = local_2360;
            local_11c = local_2364;
            local_118 = local_2368;
            local_114 = local_236c;
            piVar12 = (int *)recv(local_1d0,local_1c8,0x2000,0);
            local_1b4 = (uint)piVar12;
            iVar1 = -0x2b28531b;
            local_22f0 = local_10c;
            local_22f8 = local_110;
            if ((int)local_1b4 < 1) {
              iVar1 = 0x4e1cd785;
            }
          }
        }
        else if (iVar15 == 0x72392436) {
          uVar11 = (x.630 + -1) * x.630;
          bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) != 0;
          iVar1 = -0x7abf6e41;
          if (9 < y.631 == bVar9 && (9 < y.631 || bVar9)) {
            iVar1 = -0x1496b534;
          }
        }
        else if (iVar15 == 0x725bdf8c) {
          iVar1 = 0x1dc43ad4;
        }
      }
      else if (iVar15 < 0x79a8331c) {
        if (iVar15 == 0x7671f0ea) {
          iVar1 = 0x41da1a33;
          if (local_15c != 3) {
            iVar1 = 0x2312ff12;
          }
        }
        else if (iVar15 == 0x78de642d) {
          local_2274 = 0;
          local_228c = local_108;
          local_2280 = local_104;
          local_2278 = local_100;
          local_226c = local_fc;
          local_2268 = local_f8;
          local_2264 = local_f4;
          local_2260 = local_e4;
          local_225c = local_e0;
          goto LAB_00124fb0;
        }
      }
      else if (iVar15 == 0x79a8331c) {
        local_170 = local_b8;
        local_164 = (ushort)*local_b8;
        iVar1 = -0x1f68aec;
        if (local_164 < 4) {
          iVar1 = -0x261f274;
        }
      }
      else if (iVar15 == 0x7ea39b0d) {
LAB_00123404:
        local_2274 = 6;
        iVar1 = -0x57898e1d;
        local_225c = local_e0;
        local_2260 = local_e4;
        local_2264 = local_f4;
        local_2268 = local_f8;
        local_226c = local_fc;
        local_2278 = local_100;
        local_2280 = local_104;
        local_228c = local_108;
      }
      goto LAB_00123454;
    }
    if (0x6160ed0f < iVar15) {
      if (iVar15 < 0x67922579) {
        if (iVar15 == 0x6160ed10) {
          iVar1 = -0x63cda853;
          if (local_15c != 1) {
            iVar1 = 0x2312ff12;
          }
        }
        else if (iVar15 == 0x6344707d) {
          bVar9 = ((x.630 + -1) * x.630 & 1U) == 0;
          iVar1 = -0x5f9b6934;
          if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
            iVar1 = -0x7a424dbc;
          }
        }
      }
      else if (iVar15 == 0x67922579) {
        iVar1 = 0x389352ad;
        if ((local_158 & 1) != 0) {
          iVar1 = -0x2d822a27;
        }
      }
      else if (iVar15 == 0x683a4786) {
        puVar3 = &DAT_00141170;
        if (((local_70 ^ 0xfe) & local_70) != 0) {
          puVar3 = &DAT_00141160;
        }
        piVar12 = (int *)__android_log_print(3,&DAT_0013f18c,&DAT_00141120,puVar3);
        iVar1 = 0x1795e1ae;
      }
      goto LAB_00123454;
    }
    if (0x550ad561 < iVar15) {
      if (iVar15 == 0x550ad562) {
        piVar12 = (int *)strncpy(local_2254,(char *)(local_b8 + 1),0xf);
        uVar11 = (x.630 + -1) * x.630;
        bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) == 0;
        iVar1 = 0x4aa0451c;
        if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
          iVar1 = -0x3508da89;
        }
      }
      else if (iVar15 == 0x60bad7e7) {
        iVar1 = -0x6e22ac4;
        if (local_140 != 0) {
          iVar1 = 0x6344707d;
        }
      }
      goto LAB_00123454;
    }
    if (iVar15 != 0x5256d6fc) {
      if (iVar15 == 0x53485761) {
        uVar11 = (x.630 + -1) * x.630;
        bVar9 = ((uVar11 ^ 0xfffffffe) & uVar11) == 0;
        iVar1 = 0xc7d17dd;
        if ((y.631 >= 10 || !bVar9) && y.631 < 10 == bVar9) {
          iVar1 = -0x7cfe1991;
        }
      }
      goto LAB_00123454;
    }
  }
  local_22b8 = 0;
  iVar1 = -0x48145516;
  goto LAB_00123454;
}

