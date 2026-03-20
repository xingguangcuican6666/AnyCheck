
undefined8
Java_luna_safe_luna_MainActivity_decryptData
          (long *param_1,undefined8 param_2,undefined8 param_3,ulong param_4)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  bool bVar4;
  bool bVar5;
  int iVar6;
  undefined8 unaff_x25;
  undefined8 local_b8;
  char *local_a8;
  char *local_a0;
  ulong local_98;
  size_t local_90;
  char *local_88;
  char local_7a;
  char local_79;
  void *local_78;
  undefined8 local_70;
  undefined8 local_68;
  
  uVar2 = (x.564 + -1) * x.564;
  bVar4 = ((uVar2 ^ 0xfffffffe) & uVar2) == 0;
  bVar1 = y.565 < 10;
  iVar3 = -0xe08e1ca;
LAB_0010cf5c:
  do {
    while (iVar6 = iVar3, iVar3 = iVar6, iVar6 < 0xd3b7d0d) {
      if (iVar6 < -0x3175e8e1) {
        if (iVar6 < -0x491aab38) {
          if (iVar6 == -0x5a2b41a5) {
            local_78 = malloc(local_90);
            iVar3 = 0x1281d588;
            if (local_78 != (void *)0x0) {
              iVar3 = 0x51d11ace;
            }
          }
          else if (iVar6 == -0x56180996) {
            __android_log_print(4,&DAT_0013f18c,&DAT_0013f680);
            (**(code **)(*param_1 + 0x550))(param_1,param_3,local_a8);
            iVar3 = -0x3175e8e1;
          }
          else if (iVar6 == -0x4c57ebd3) {
            __android_log_print(4,&DAT_0013f18c,&DAT_0013f6b0);
            free(local_88);
            (**(code **)(*param_1 + 0x550))(param_1,param_3,local_a8);
            iVar3 = -0x181dd1be;
          }
        }
        else {
          iVar3 = 0x389dfb2d;
          if (iVar6 != -0x491aab38) {
            if (iVar6 == -0x4303694a) {
              base64_decode((long)local_a8,local_98,(long)local_88,param_4);
              uVar2 = (x.564 + -1) * x.564;
              local_79 = *local_88 == '\0';
              bVar5 = ((uVar2 ^ 0xfffffffe) & uVar2) == 0;
              iVar3 = 0x4b32415a;
              if (y.565 < 10 == bVar5 && (9 < y.565 || !bVar5)) {
                iVar3 = 0x986388;
              }
            }
            else {
              iVar3 = iVar6;
              if (iVar6 == -0x37139903) {
LAB_0010cf50:
                unaff_x25 = 0;
                iVar3 = 0x1b33badc;
              }
            }
          }
        }
      }
      else if (iVar6 < -0x15a7841c) {
        if (iVar6 == -0x3175e8e1) {
          __android_log_print(4,&DAT_0013f18c,&DAT_0013f680);
          (**(code **)(*param_1 + 0x550))(param_1,param_3,local_a8);
          uVar2 = (x.564 + -1) * x.564;
          bVar5 = ((uVar2 ^ 0xfffffffe) & uVar2) == 0;
          iVar3 = -0x37139903;
          if ((y.565 >= 10 || !bVar5) && y.565 < 10 == bVar5) {
            iVar3 = -0x56180996;
          }
        }
        else if (iVar6 == -0x2a429bd3) {
          bVar5 = ((x.564 + -1) * x.564 & 1U) == 0;
          iVar3 = -0x3175e8e1;
          if ((y.565 >= 10 || !bVar5) && y.565 < 10 == bVar5) {
            iVar3 = -0x56180996;
          }
        }
        else if (iVar6 == -0x181dd1be) {
          __android_log_print(4,&DAT_0013f18c,&DAT_0013f6b0);
          free(local_88);
          (**(code **)(*param_1 + 0x550))(param_1,param_3,local_a8);
          uVar2 = (x.564 + -1) * x.564 & 1;
          iVar3 = 0x71370977;
          if (y.565 < 10 == (uVar2 == 0) && (9 < y.565 | uVar2) == 1) {
            iVar3 = -0x4c57ebd3;
          }
        }
      }
      else if (iVar6 < 0x986388) {
        if (iVar6 == -0x15a7841c) {
          local_70 = local_b8;
          bVar5 = ((x.564 + -1) * x.564 & 1U) == 0;
          iVar3 = 0x389dfb2d;
          if ((y.565 >= 10 || !bVar5) && y.565 < 10 == bVar5) {
            iVar3 = -0x491aab38;
          }
        }
        else if (iVar6 == -0xe08e1ca) {
          iVar3 = 0x7d2cba45;
          if ((!bVar4 || !bVar1) && bVar4 == bVar1) {
            iVar3 = 0xcb2dc6b;
          }
        }
      }
      else if (iVar6 == 0x986388) {
        base64_decode((long)local_a8,local_98,(long)local_88,param_4);
        iVar3 = -0x4303694a;
      }
      else if (iVar6 == 0xcb2dc6b) {
        (**(code **)(*param_1 + 0x548))(param_1,param_3,0);
        iVar3 = 0x7d2cba45;
      }
    }
    if (0x3e2b47cc < iVar6) {
      if (iVar6 < 0x51d11ace) {
        if (iVar6 == 0x3e2b47cd) {
          iVar3 = -0x2a429bd3;
          if (local_7a == '\0') {
            iVar3 = 0x44ff9a6b;
          }
        }
        else if (iVar6 == 0x44ff9a6b) {
          uVar2 = (x.564 + -1) * x.564;
          bVar5 = ((uVar2 ^ 0xfffffffe) & uVar2) != 0;
          iVar3 = -0x4303694a;
          if (9 < y.565 == bVar5 && (9 < y.565 || bVar5)) {
            iVar3 = 0x986388;
          }
        }
        else if (iVar6 == 0x4b32415a) {
          iVar3 = 0x39ccab3c;
          if (local_79 == '\0') {
            iVar3 = -0x5a2b41a5;
          }
        }
      }
      else if (iVar6 < 0x71370977) {
        if (iVar6 == 0x51d11ace) {
          xorEncryptDecrypt(local_88,(long)local_78,local_a0);
          local_b8 = (**(code **)(*param_1 + 0x538))(param_1,local_78);
          free(local_88);
          free(local_78);
          (**(code **)(*param_1 + 0x550))(param_1,param_3,local_a8);
          iVar3 = -0x15a7841c;
        }
        else if (iVar6 == 0x6d95fe4e) {
          return local_68;
        }
      }
      else {
        if (iVar6 == 0x71370977) goto LAB_0010cf50;
        if (iVar6 == 0x7d2cba45) {
          local_a8 = (char *)(**(code **)(*param_1 + 0x548))(param_1,param_3,0);
          local_a0 = (char *)&DAT_0013f668;
          local_98 = strlen(local_a8);
          local_90 = local_98 + 1;
          local_88 = malloc(local_90);
          local_7a = local_88 == (char *)0x0;
          bVar5 = ((x.564 + -1) * x.564 & 1U) == 0;
          iVar3 = 0x3e2b47cd;
          if ((y.565 >= 10 || !bVar5) && y.565 < 10 == bVar5) {
            iVar3 = 0xcb2dc6b;
          }
        }
      }
      goto LAB_0010cf5c;
    }
    if (iVar6 < 0x302401ad) {
      if (iVar6 == 0xd3b7d0d) {
        bVar5 = ((x.564 + -1) * x.564 & 1U) == 0;
        iVar3 = 0x6d95fe4e;
        if ((y.565 >= 10 || !bVar5) && y.565 < 10 == bVar5) {
          iVar3 = 0x38756681;
        }
      }
      else if (iVar6 == 0x1281d588) {
        __android_log_print(4,&DAT_0013f18c,&DAT_0013f6d0);
        free(local_88);
        (**(code **)(*param_1 + 0x550))(param_1,param_3,local_a8);
        local_b8 = 0;
        iVar3 = -0x15a7841c;
      }
      else if (iVar6 == 0x1b33badc) {
        uVar2 = (x.564 + -1) * x.564;
        bVar5 = ((uVar2 ^ 0xfffffffe) & uVar2) == 0;
        iVar3 = 0xd3b7d0d;
        local_68 = unaff_x25;
        if ((y.565 >= 10 || !bVar5) && y.565 < 10 == bVar5) {
          iVar3 = 0x38756681;
        }
      }
    }
    else if (iVar6 < 0x389dfb2d) {
      if (iVar6 == 0x302401ad) {
        unaff_x25 = local_70;
        iVar3 = 0x1b33badc;
      }
      else if (iVar6 == 0x38756681) {
        iVar3 = 0xd3b7d0d;
      }
    }
    else if (iVar6 == 0x389dfb2d) {
      uVar2 = (x.564 + -1) * x.564 & 1;
      iVar3 = 0x302401ad;
      if (y.565 < 10 == (uVar2 == 0) && (9 < y.565 | uVar2) == 1) {
        iVar3 = -0x491aab38;
      }
    }
    else if (iVar6 == 0x39ccab3c) {
      uVar2 = (x.564 + -1) * x.564;
      bVar5 = ((uVar2 ^ 0xfffffffe) & uVar2) == 0;
      iVar3 = -0x181dd1be;
      if ((y.565 >= 10 || !bVar5) && y.565 < 10 == bVar5) {
        iVar3 = -0x4c57ebd3;
      }
    }
  } while( true );
}

