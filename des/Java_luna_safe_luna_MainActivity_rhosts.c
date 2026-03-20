
undefined8 Java_luna_safe_luna_MainActivity_rhosts(long *param_1)

{
  uint uVar1;
  bool bVar2;
  size_t sVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  int iVar6;
  undefined8 unaff_x20;
  FILE *unaff_x21;
  ulong unaff_x24;
  undefined8 unaff_x26;
  code *pcVar7;
  uint local_f4;
  int local_f0;
  uint local_ec;
  char acStack_e8 [32];
  char acStack_c8 [32];
  FILE *local_a8;
  size_t local_a0;
  void *local_98;
  char local_89;
  ulong local_88;
  ulong local_80;
  char local_71;
  FILE *local_70;
  int local_68;
  uint local_64;
  
  local_a8 = fopen(&DAT_0013fe10,&DAT_0013f0f4);
  iVar6 = -0x568c2cb1;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          while( true ) {
            while (iVar6 < 0x4b1d0e4) {
              if (iVar6 < -0x5673a846) {
                if (iVar6 < -0x72007110) {
                  if (iVar6 == -0x7aabe5b5) {
                    unaff_x21 = fopen((char *)&DAT_0013fe28,&DAT_0013f0f4);
                    iVar6 = -0x53901ad2;
                    if (unaff_x21 != (FILE *)0x0) {
                      iVar6 = -0x72007110;
                    }
                  }
                  else if (iVar6 == -0x77fe6a6e) {
                    local_ec = local_64;
                    iVar6 = 0x5898841a;
                    if (local_71 == '\0') {
                      iVar6 = 0x75095fe7;
                    }
                  }
                  else if (iVar6 == -0x765a4da6) {
                    local_88 = fread(local_98,1,local_a0,local_70);
                    *(undefined1 *)((long)local_98 + local_88) = 0;
                    uVar1 = (x.596 + -1) * x.596;
                    bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
                    iVar6 = 0x4e7a8287;
                    if (9 < y.597 == bVar2 && (9 < y.597 || bVar2)) {
                      iVar6 = 0x1c403225;
                    }
                  }
                }
                else if (iVar6 == -0x72007110) {
                  uVar1 = (x.596 + -1) * x.596;
                  bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                  iVar6 = -0x2871ed2e;
                  local_70 = unaff_x21;
                  if (y.597 < 10 == bVar2 && (9 < y.597 || !bVar2)) {
                    iVar6 = 0x27a2eb77;
                  }
                }
                else if (iVar6 == -0x61b041c0) {
                  local_68 = local_f0;
                  local_64 = local_f4;
                  local_80 = (ulong)local_f0;
                  iVar6 = 0x65ec66b9;
                  if (local_88 <= local_80) {
                    iVar6 = 0x66acca5c;
                  }
                }
                else if (iVar6 == -0x568c2cb1) {
                  unaff_x21 = local_a8;
                  iVar6 = -0x7aabe5b5;
                  if (local_a8 != (FILE *)0x0) {
                    iVar6 = -0x72007110;
                  }
                }
              }
              else if (iVar6 < -0x306b8972) {
                if (iVar6 == -0x5673a846) {
                  unaff_x24 = (ulong)local_64;
                  iVar6 = -0x19c0304a;
                  if (*(char *)((long)local_98 + (local_88 - 1)) != '\n') {
                    iVar6 = 0x206ad5f3;
                  }
                }
                else if (iVar6 == -0x53901ad2) {
                  pcVar7 = *(code **)(*param_1 + 0x560);
                  uVar4 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
                  uVar5 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_001051d1);
                  unaff_x26 = (*pcVar7)(param_1,3,uVar4,uVar5);
                  pcVar7 = *(code **)(*param_1 + 0x570);
                  uVar4 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_0013fe40);
                  (*pcVar7)(param_1,unaff_x26,0,uVar4);
                  pcVar7 = *(code **)(*param_1 + 0x570);
                  uVar4 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_0013fe58);
                  (*pcVar7)(param_1,unaff_x26,1,uVar4);
                  pcVar7 = *(code **)(*param_1 + 0x570);
                  uVar4 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_0013fe58);
                  (*pcVar7)(param_1,unaff_x26,2,uVar4);
                  iVar6 = 0x55b7a27b;
                }
                else if (iVar6 == -0x46216995) {
                  unaff_x26 = unaff_x20;
                  iVar6 = 0x55b7a27b;
                }
              }
              else if (iVar6 == -0x306b8972) {
                iVar6 = 0x4b1d0e4;
              }
              else if (iVar6 == -0x2871ed2e) {
                fseek(local_70,0,2);
                local_a0 = ftell(local_70);
                fseek(local_70,0,0);
                local_98 = malloc(local_a0 + 1);
                local_89 = local_98 == (void *)0x0;
                uVar1 = (x.596 + -1) * x.596 & 1;
                iVar6 = 0x49a4dad6;
                if (9 < y.597 == uVar1 && (9 < y.597 | uVar1) == 1) {
                  iVar6 = 0x27a2eb77;
                }
              }
              else if (iVar6 == -0x19c0304a) {
                pcVar7 = *(code **)(*param_1 + 0x560);
                uVar4 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
                uVar5 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_001051d1);
                unaff_x20 = (*pcVar7)(param_1,3,uVar4,uVar5);
                pcVar7 = *(code **)(*param_1 + 0x570);
                uVar4 = (**(code **)(*param_1 + 0x538))(param_1,local_98);
                (*pcVar7)(param_1,unaff_x20,0,uVar4);
                sprintf(acStack_c8,&DAT_0013fe74,unaff_x24 & 0xffffffff);
                pcVar7 = *(code **)(*param_1 + 0x570);
                uVar4 = (**(code **)(*param_1 + 0x538))(param_1,acStack_c8);
                (*pcVar7)(param_1,unaff_x20,1,uVar4);
                sprintf(acStack_e8,&DAT_0013fe78,local_a0);
                pcVar7 = *(code **)(*param_1 + 0x570);
                uVar4 = (**(code **)(*param_1 + 0x538))(param_1,acStack_e8);
                (*pcVar7)(param_1,unaff_x20,2,uVar4);
                free(local_98);
                fclose(local_70);
                iVar6 = -0x46216995;
              }
            }
            if (0x4e7a8286 < iVar6) break;
            if (iVar6 < 0x27a2eb77) {
              if (iVar6 == 0x4b1d0e4) {
                uVar1 = (x.596 + -1) * x.596;
                local_71 = *(char *)((long)local_98 + local_80) == '\n';
                bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                iVar6 = -0x77fe6a6e;
                if ((y.597 >= 10 || !bVar2) && y.597 < 10 == bVar2) {
                  iVar6 = -0x306b8972;
                }
              }
              else if (iVar6 == 0x1c403225) {
                sVar3 = fread(local_98,1,local_a0,local_70);
                *(undefined1 *)((long)local_98 + sVar3) = 0;
                iVar6 = -0x765a4da6;
              }
              else if (iVar6 == 0x206ad5f3) {
                unaff_x24 = (ulong)(local_64 + 1);
                iVar6 = -0x19c0304a;
              }
            }
            else if (iVar6 == 0x27a2eb77) {
              fseek(local_70,0,2);
              ftell(local_70);
              fseek(local_70,0,0);
              iVar6 = -0x2871ed2e;
            }
            else if (iVar6 == 0x3fe16d5b) {
              fclose(local_70);
              pcVar7 = *(code **)(*param_1 + 0x560);
              uVar4 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
              uVar5 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_001051d1);
              unaff_x20 = (*pcVar7)(param_1,3,uVar4,uVar5);
              pcVar7 = *(code **)(*param_1 + 0x570);
              uVar4 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_0013fe60);
              (*pcVar7)(param_1,unaff_x20,0,uVar4);
              pcVar7 = *(code **)(*param_1 + 0x570);
              uVar4 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_0013fe58);
              (*pcVar7)(param_1,unaff_x20,1,uVar4);
              pcVar7 = *(code **)(*param_1 + 0x570);
              uVar4 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_0013fe58);
              (*pcVar7)(param_1,unaff_x20,2,uVar4);
              iVar6 = -0x46216995;
            }
            else if (iVar6 == 0x49a4dad6) {
              iVar6 = 0x3fe16d5b;
              if (local_89 == '\0') {
                iVar6 = 0x76d9ffa0;
              }
            }
          }
          if (iVar6 < 0x66acca5c) break;
          if (iVar6 == 0x66acca5c) {
            unaff_x24 = (ulong)local_64;
            iVar6 = -0x19c0304a;
            if (local_88 != 0) {
              iVar6 = -0x5673a846;
            }
          }
          else if (iVar6 == 0x75095fe7) {
            local_f4 = local_ec;
            local_f0 = local_68 + 1;
            iVar6 = -0x61b041c0;
          }
          else if (iVar6 == 0x76d9ffa0) {
            uVar1 = (x.596 + -1) * x.596;
            bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
            iVar6 = -0x765a4da6;
            if (y.597 < 10 == bVar2 && (9 < y.597 || !bVar2)) {
              iVar6 = 0x1c403225;
            }
          }
        }
        if (iVar6 < 0x5898841a) break;
        if (iVar6 == 0x5898841a) {
          local_ec = local_64 + 1;
          iVar6 = 0x75095fe7;
        }
        else if (iVar6 == 0x65ec66b9) {
          uVar1 = (x.596 + -1) * x.596;
          bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
          iVar6 = 0x4b1d0e4;
          if ((y.597 >= 10 || !bVar2) && y.597 < 10 == bVar2) {
            iVar6 = -0x306b8972;
          }
        }
      }
      if (iVar6 != 0x4e7a8287) break;
      local_f4 = 0;
      local_f0 = 0;
      iVar6 = -0x61b041c0;
    }
  } while (iVar6 != 0x55b7a27b);
  return unaff_x26;
}

