
undefined8 Java_luna_safe_luna_MainActivity_procscan(long *param_1)

{
  uint uVar1;
  bool bVar2;
  char *pcVar3;
  int iVar4;
  char *pcVar5;
  undefined1 auStack_180 [8];
  undefined8 local_178;
  undefined8 local_170;
  undefined8 local_168;
  int local_15c;
  int local_158;
  int local_154;
  undefined8 local_150;
  undefined8 local_148;
  int local_140;
  int local_13c;
  undefined8 local_138;
  byte local_12a;
  byte local_129;
  char *local_128;
  char *local_120;
  char *local_118;
  char *local_110;
  char *local_108;
  char *local_100;
  ulong local_f8;
  char *local_f0;
  FILE *local_e8;
  char *local_e0;
  char local_d2;
  char local_d1;
  ulong local_d0;
  char local_c1;
  char *local_c0;
  char *local_b8;
  undefined8 local_b0;
  int local_a4;
  undefined8 local_a0;
  undefined8 local_98;
  int local_8c;
  undefined8 local_88;
  int local_7c;
  undefined8 local_78;
  int local_6c;
  
  pcVar5 = auStack_180;
  uVar1 = (x.626 + -1) * x.626;
  local_12a = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
  local_129 = y.627 < 10;
  iVar4 = 0x3eed3f34;
LAB_00121324:
  while (-0x603bfa1 < iVar4) {
    if (iVar4 < 0x2e3ac8b6) {
      if (iVar4 < 0xc31b514) {
        if (iVar4 < 0xf0355c) {
          if (iVar4 == -0x603bfa0) {
            uVar1 = (x.626 + -1) * x.626;
            bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
            iVar4 = 0x1da6fc8a;
            if (y.627 < 10 == bVar2 && (9 < y.627 || !bVar2)) {
              iVar4 = 0xadabb54;
            }
          }
          else if (iVar4 == -0x2337fb6) {
            local_88 = local_168;
            local_e0 = local_118;
            pcVar3 = fgets(local_118,0x400,local_e8);
            iVar4 = 0x45419aa5;
            if (pcVar3 != (char *)0x0) {
              iVar4 = -0x539b5bb3;
            }
          }
          else if (iVar4 == 0xaf7430) {
            bVar2 = ((x.626 + -1) * x.626 & 1U) == 0;
            iVar4 = -0x603bfa0;
            if ((y.627 >= 10 || !bVar2) && y.627 < 10 == bVar2) {
              iVar4 = 0xadabb54;
            }
          }
        }
        else if (iVar4 < 0x70888fe) {
          if (iVar4 == 0xf0355c) {
            uVar1 = (x.626 + -1) * x.626 & 1;
            iVar4 = -0x7c8dd25c;
            if (9 < y.627 == uVar1 && (9 < y.627 | uVar1) == 1) {
              iVar4 = -0x56dc62fa;
            }
          }
          else if (iVar4 == 0x54c94d8) {
            iVar4 = -0x4435b291;
          }
        }
        else if (iVar4 == 0x70888fe) {
          __android_log_print(4,&DAT_0013f18c,&DAT_00140a40);
          local_a0 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_001051d1);
          uVar1 = (x.626 + -1) * x.626 & 1;
          iVar4 = -0x2aaf4de7;
          if (y.627 < 10 == (uVar1 == 0) && (9 < y.627 | uVar1) == 1) {
            iVar4 = 0x78bdbea8;
          }
        }
        else if (iVar4 == 0xadabb54) {
          iVar4 = -0x603bfa0;
        }
      }
      else if (iVar4 < 0x1da6fc8a) {
        if (iVar4 == 0xc31b514) {
          local_15c = 0;
          iVar4 = -0x7ecfff97;
        }
        else if (iVar4 == 0xdf501b0) {
          local_138 = local_98;
          local_13c = 4;
LAB_001222a0:
          iVar4 = 0x66bfc987;
        }
        else if (iVar4 == 0x1ac2ea88) {
          uVar1 = (x.626 + -1) * x.626;
          bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
          iVar4 = 0x70888fe;
          if ((y.627 >= 10 || !bVar2) && y.627 < 10 == bVar2) {
            iVar4 = 0x78bdbea8;
          }
        }
      }
      else if (iVar4 < 0x2a9aa812) {
        if (iVar4 == 0x1da6fc8a) {
          local_150 = local_88;
          local_154 = 7;
LAB_00121318:
          iVar4 = 0x6ef12cd1;
        }
        else if (iVar4 == 0x1ec21121) {
          iVar4 = 0x1ac2ea88;
          if (local_140 != 2) {
            iVar4 = 0x2a9aa812;
          }
          local_170 = local_148;
        }
      }
      else if (iVar4 == 0x2ca8f317) {
        iVar4 = 0x38093bc8;
        if (local_c1 == '\0') {
          iVar4 = 0xaf7430;
        }
      }
      else if (iVar4 == 0x2a9aa812) {
        return local_170;
      }
    }
    else if (iVar4 < 0x5ac7484e) {
      if (iVar4 < 0x3f54269f) {
        if (iVar4 == 0x2e3ac8b6) {
          iVar4 = -0x5f716cb9;
        }
        else if (iVar4 == 0x38093bc8) {
          local_c0 = local_128 + local_d0 * 8;
          local_b8 = *(char **)local_c0;
          pcVar3 = strstr(local_e0,local_b8);
          iVar4 = 0xf0355c;
          if (pcVar3 != (char *)0x0) {
            iVar4 = -0x4e4b1742;
          }
        }
        else if (iVar4 == 0x3eed3f34) {
          iVar4 = 0x7c2f9fee;
          if (((local_12a ^ 1 ^ local_129 ^ 1 | (local_12a ^ 1 | local_129 ^ 1) ^ 0xff) & 1) == 0) {
            iVar4 = -0x4229326f;
          }
        }
      }
      else if (iVar4 < 0x47ed3f01) {
        if (iVar4 == 0x3f54269f) {
          iVar4 = -0x2b484cf2;
        }
        else if (iVar4 == 0x45419aa5) {
          fclose(local_e8);
          __android_log_print(4,&DAT_0013f18c,&DAT_00140a20,local_f0);
          local_13c = 0;
          local_138 = local_88;
          iVar4 = 0x66bfc987;
        }
      }
      else if (iVar4 == 0x47ed3f01) {
        local_15c = local_a4;
        iVar4 = -0x7ecfff97;
      }
      else if (iVar4 == 0x4b1bff8c) {
        local_158 = 0;
        iVar4 = -0x28e42640;
      }
    }
    else if (iVar4 < 0x6ef12cd1) {
      if (iVar4 == 0x5ac7484e) {
        bVar2 = ((x.626 + -1) * x.626 & 1U) == 0;
        iVar4 = 0x3f54269f;
        if ((y.627 >= 10 || !bVar2) && y.627 < 10 == bVar2) {
          iVar4 = -0x6a02b4ff;
        }
      }
      else if (iVar4 == 0x649de539) {
        local_178 = local_78;
        local_158 = local_8c + 1;
        iVar4 = -0x28e42640;
      }
      else if (iVar4 == 0x66bfc987) {
        local_78 = local_138;
        local_6c = local_13c;
        uVar1 = (x.626 + -1) * x.626 & 1;
        iVar4 = 0x5ac7484e;
        if (y.627 < 10 == (uVar1 == 0) && (9 < y.627 | uVar1) == 1) {
          iVar4 = -0x6a02b4ff;
        }
      }
    }
    else if (iVar4 < 0x7c2f9fee) {
      if (iVar4 == 0x6ef12cd1) {
        iVar4 = -0x2337fb6;
        if (local_154 != 7) {
          iVar4 = 0x66bfc987;
        }
        local_13c = local_154;
        local_138 = local_150;
        local_168 = local_150;
      }
      else if (iVar4 == 0x78bdbea8) {
        __android_log_print(4,&DAT_0013f18c,&DAT_00140a40);
        (**(code **)(*param_1 + 0x538))(param_1,&DAT_001051d1);
        iVar4 = 0x70888fe;
      }
    }
    else if (iVar4 == 0x7c2f9fee) {
      local_128 = pcVar5 + -0x30;
      local_120 = pcVar5 + -0x50;
      pcVar5 = pcVar5 + -0x450;
      local_118 = pcVar5;
      __android_log_print(4,&DAT_0013f18c,&DAT_00140810);
      local_110 = local_128;
      pcVar3 = local_128;
      pcVar3[8] = '\0';
      pcVar3[9] = '\0';
      pcVar3[10] = '\0';
      pcVar3[0xb] = '\0';
      pcVar3[0xc] = '\0';
      pcVar3[0xd] = '\0';
      pcVar3[0xe] = '\0';
      pcVar3[0xf] = '\0';
      pcVar3[0] = '\0';
      pcVar3[1] = '\0';
      pcVar3[2] = '\0';
      pcVar3[3] = '\0';
      pcVar3[4] = '\0';
      pcVar3[5] = '\0';
      pcVar3[6] = '\0';
      pcVar3[7] = '\0';
      pcVar3[0x18] = '\0';
      pcVar3[0x19] = '\0';
      pcVar3[0x1a] = '\0';
      pcVar3[0x1b] = '\0';
      pcVar3[0x1c] = '\0';
      pcVar3[0x1d] = '\0';
      pcVar3[0x1e] = '\0';
      pcVar3[0x1f] = '\0';
      pcVar3[0x10] = '\0';
      pcVar3[0x11] = '\0';
      pcVar3[0x12] = '\0';
      pcVar3[0x13] = '\0';
      pcVar3[0x14] = '\0';
      pcVar3[0x15] = '\0';
      pcVar3[0x16] = '\0';
      pcVar3[0x17] = '\0';
      pcVar3[0x20] = '\0';
      pcVar3[0x21] = '\0';
      pcVar3[0x22] = '\0';
      pcVar3[0x23] = '\0';
      pcVar3[0x24] = '\0';
      pcVar3[0x25] = '\0';
      pcVar3[0x26] = '\0';
      pcVar3[0x27] = '\0';
      *(undefined8 **)local_128 = &DAT_00140820;
      *(undefined1 **)(local_128 + 8) = &DAT_00140828;
      *(undefined8 **)(local_128 + 0x10) = &DAT_00140830;
      *(undefined8 **)(local_128 + 0x18) = &DAT_00140838;
      *(undefined8 **)(local_128 + 0x20) = &DAT_00140840;
      pcVar3 = local_120;
      local_108 = local_120;
      *(undefined8 **)(local_120 + 8) = &DAT_00140868;
      *(undefined **)pcVar3 = &DAT_00140850;
      *(undefined **)(pcVar3 + 0x10) = &DAT_00140880;
      local_100 = local_118;
      uVar1 = (x.626 + -1) * x.626 & 1;
      iVar4 = 0x4b1bff8c;
      if (y.627 < 10 == (uVar1 == 0) && (9 < y.627 | uVar1) == 1) {
        iVar4 = -0x4229326f;
      }
    }
    else if (iVar4 == 0x7c6e4369) {
      __android_log_print(4,&DAT_0013f18c,&DAT_001409a0,local_f0,local_b8,local_e0);
      fclose(local_e8);
      __android_log_print(4,&DAT_0013f18c,&DAT_001409e0,*(undefined8 *)local_c0,local_f0);
      (**(code **)(*param_1 + 0x538))(param_1,*(undefined8 *)local_c0);
      iVar4 = -0x20442d98;
    }
  }
  if (iVar4 < -0x487497fe) {
    if (-0x5f716cba < iVar4) {
      if (iVar4 < -0x56dc62fa) {
        if (iVar4 == -0x5f716cb9) {
          pcVar3 = strstr(local_e0,s_6/<+58_Y_00140910);
          local_d1 = pcVar3 != (char *)0x0;
          bVar2 = ((x.626 + -1) * x.626 & 1U) == 0;
          iVar4 = -0xc2365cc;
          if ((y.627 >= 10 || !bVar2) && y.627 < 10 == bVar2) {
            iVar4 = 0x2e3ac8b6;
          }
        }
        else if (iVar4 == -0x5e0a82d2) {
          iVar4 = -0x19767f08;
          if (local_d2 == '\0') {
            iVar4 = 0xc31b514;
          }
        }
        else if (iVar4 == -0x57af4dfe) {
          bVar2 = ((x.626 + -1) * x.626 & 1U) == 0;
          iVar4 = -0x3ca7930f;
          if ((y.627 >= 10 || !bVar2) && y.627 < 10 == bVar2) {
            iVar4 = -0x657713eb;
          }
        }
      }
      else if (iVar4 < -0x4e4b1742) {
        if (iVar4 == -0x56dc62fa) {
          iVar4 = -0x7c8dd25c;
        }
        else if (iVar4 == -0x539b5bb3) {
          uVar1 = (x.626 + -1) * x.626 & 1;
          iVar4 = -0x487497fe;
          if (9 < y.627 == uVar1 && (9 < y.627 | uVar1) == 1) {
            iVar4 = -0x6d445d1e;
          }
        }
      }
      else if (iVar4 == -0x4e4b1742) {
        uVar1 = (x.626 + -1) * x.626;
        bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
        iVar4 = -0x20442d98;
        if ((y.627 >= 10 || !bVar2) && y.627 < 10 == bVar2) {
          iVar4 = 0x7c6e4369;
        }
      }
      else if (iVar4 == -0x4b916ebb) {
        local_f0 = *(char **)(local_120 + local_f8 * 8);
        __android_log_print(4,&DAT_0013f18c,&DAT_001408a0,local_f0);
        local_e8 = fopen(local_f0,&DAT_0013f0f4);
        local_168 = local_98;
        iVar4 = -0x57af4dfe;
        if (local_e8 != (FILE *)0x0) {
          iVar4 = -0x2337fb6;
        }
      }
      goto LAB_00121324;
    }
    if (-0x6d445d1f < iVar4) {
      if (iVar4 < -0x6919be34) {
        if (iVar4 == -0x6d445d1e) {
          __android_log_print(4,&DAT_0013f18c,&DAT_001408e0,local_f0,local_e0);
          iVar4 = -0x487497fe;
        }
        else if (iVar4 == -0x6a02b4ff) {
          iVar4 = 0x5ac7484e;
        }
      }
      else if (iVar4 == -0x6919be34) {
        local_148 = local_98;
        local_140 = 2;
        iVar4 = 0x1ec21121;
      }
      else if (iVar4 == -0x657713eb) {
        __android_log_print(4,&DAT_0013f18c,&DAT_001408c0,local_f0);
        iVar4 = -0x3ca7930f;
      }
      goto LAB_00121324;
    }
    if (iVar4 == -0x7ecfff97) {
      local_7c = local_15c;
      bVar2 = ((x.626 + -1) * x.626 & 1U) == 0;
      iVar4 = -0x4435b291;
      if ((y.627 >= 10 || !bVar2) && y.627 < 10 == bVar2) {
        iVar4 = 0x54c94d8;
      }
      goto LAB_00121324;
    }
    if (iVar4 == -0x7c8dd25c) {
      local_a4 = local_7c + 1;
      uVar1 = (x.626 + -1) * x.626;
      bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
      iVar4 = 0x47ed3f01;
      if (9 < y.627 == bVar2 && (9 < y.627 || bVar2)) {
        iVar4 = -0x56dc62fa;
      }
      goto LAB_00121324;
    }
    if (iVar4 != -0x76dbfc94) goto LAB_00121324;
    bVar2 = local_6c == 0;
  }
  else {
    if (-0x301c9d74 < iVar4) {
      if (iVar4 < -0x28e42640) {
        if (iVar4 == -0x301c9d73) {
          __android_log_print(4,&DAT_0013f18c,&DAT_00140920,local_f0,local_e0);
          fclose(local_e8);
          __android_log_print(4,&DAT_0013f18c,&DAT_00140960,local_f0);
          local_138 = (**(code **)(*param_1 + 0x538))(param_1,s_6/<+58_Y_00140910);
          local_13c = 1;
          goto LAB_001222a0;
        }
        if (iVar4 == -0x2b484cf2) {
          iVar4 = -0x76dbfc94;
          if (3 < local_6c) {
            iVar4 = -0x43387aac;
          }
        }
        else if (iVar4 == -0x2aaf4de7) {
          local_170 = local_a0;
          iVar4 = 0x2a9aa812;
        }
      }
      else if (iVar4 < -0x19767f08) {
        if (iVar4 == -0x28e42640) {
          local_98 = local_178;
          local_8c = local_158;
          local_f8 = (ulong)local_158;
          iVar4 = -0x4b916ebb;
          if (2 < local_f8) {
            iVar4 = -0x6919be34;
          }
        }
        else if (iVar4 == -0x20442d98) {
          __android_log_print(4,&DAT_0013f18c,&DAT_001409a0,local_f0,local_b8,local_e0);
          fclose(local_e8);
          __android_log_print(4,&DAT_0013f18c,&DAT_001409e0,*(undefined8 *)local_c0,local_f0);
          local_b0 = (**(code **)(*param_1 + 0x538))(param_1,*(undefined8 *)local_c0);
          uVar1 = (x.626 + -1) * x.626;
          bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
          iVar4 = -0x44ba36d1;
          if (9 < y.627 == bVar2 && (9 < y.627 || bVar2)) {
            iVar4 = 0x7c6e4369;
          }
        }
      }
      else if (iVar4 == -0x19767f08) {
        uVar1 = (x.626 + -1) * x.626 & 1;
        iVar4 = -0x5f716cb9;
        if (9 < y.627 == uVar1 && (9 < y.627 | uVar1) == 1) {
          iVar4 = 0x2e3ac8b6;
        }
      }
      else if (iVar4 == -0xc2365cc) {
        iVar4 = -0x301c9d73;
        if (local_d1 == '\0') {
          iVar4 = 0xc31b514;
        }
      }
      goto LAB_00121324;
    }
    if (iVar4 < -0x43387aac) {
      if (iVar4 == -0x487497fe) {
        __android_log_print(4,&DAT_0013f18c,&DAT_001408e0,local_f0,local_e0);
        pcVar3 = strstr(local_e0,(char *)&DAT_00140900);
        local_d2 = pcVar3 != (char *)0x0;
        uVar1 = (x.626 + -1) * x.626;
        bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
        iVar4 = -0x5e0a82d2;
        if ((y.627 >= 10 || !bVar2) && y.627 < 10 == bVar2) {
          iVar4 = -0x6d445d1e;
        }
      }
      else {
        if (iVar4 == -0x44ba36d1) {
          local_150 = local_b0;
          local_154 = 1;
          goto LAB_00121318;
        }
        if (iVar4 == -0x4435b291) {
          local_d0 = (ulong)local_7c;
          local_c1 = local_d0 < 5;
          uVar1 = (x.626 + -1) * x.626;
          bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
          iVar4 = 0x2ca8f317;
          if ((y.627 >= 10 || !bVar2) && y.627 < 10 == bVar2) {
            iVar4 = 0x54c94d8;
          }
        }
      }
      goto LAB_00121324;
    }
    if (-0x3ca79310 < iVar4) {
      if (iVar4 == -0x3ca7930f) {
        __android_log_print(4,&DAT_0013f18c,&DAT_001408c0,local_f0);
        uVar1 = (x.626 + -1) * x.626 & 1;
        iVar4 = 0xdf501b0;
        if (y.627 < 10 == (uVar1 == 0) && (9 < y.627 | uVar1) == 1) {
          iVar4 = -0x657713eb;
        }
      }
      else if (iVar4 == -0x3ac187ce) {
        local_140 = local_6c;
        local_148 = local_78;
        iVar4 = 0x1ec21121;
      }
      goto LAB_00121324;
    }
    if (iVar4 != -0x43387aac) {
      if (iVar4 == -0x4229326f) {
        __android_log_print(4,&DAT_0013f18c,&DAT_00140810);
        iVar4 = 0x7c2f9fee;
      }
      goto LAB_00121324;
    }
    bVar2 = local_6c == 4;
  }
  iVar4 = 0x649de539;
  if (!bVar2) {
    iVar4 = -0x3ac187ce;
  }
  goto LAB_00121324;
}

