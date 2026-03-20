
undefined8 Java_luna_safe_luna_MainActivity_bugfind(long *param_1)

{
  uint uVar1;
  char *__name;
  char *pcVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  undefined1 auStack_150 [8];
  undefined8 uStack_148;
  undefined8 uStack_140;
  int iStack_138;
  int iStack_134;
  undefined8 uStack_130;
  undefined8 uStack_128;
  int iStack_11c;
  undefined8 uStack_118;
  int iStack_10c;
  undefined8 uStack_108;
  int iStack_100;
  byte bStack_fa;
  byte bStack_f9;
  char *pcStack_f8;
  char *pcStack_f0;
  char *pcStack_e8;
  ulong uStack_e0;
  ulong uStack_d8;
  char cStack_c9;
  char *pcStack_c8;
  char *pcStack_c0;
  undefined **ppuStack_b8;
  char cStack_a9;
  undefined8 uStack_a8;
  char cStack_9d;
  int iStack_9c;
  undefined8 uStack_98;
  int iStack_8c;
  undefined8 uStack_88;
  undefined8 uStack_80;
  int iStack_74;
  undefined8 uStack_70;
  
  uVar1 = (x.602 + -1) * x.602;
  bStack_fa = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
  bStack_f9 = y.603 < 10;
  pcVar2 = auStack_150;
  iVar4 = -0x1bec0569;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          while( true ) {
            while( true ) {
              while (iVar5 = iVar4, __name = pcStack_f0, iVar4 = iVar5, iVar5 < 0x2ef476a) {
                if (iVar5 < -0x46ee5f92) {
                  if (iVar5 < -0x654b1ecd) {
                    if (iVar5 < -0x72acc27c) {
                      if (iVar5 == -0x7e5952e3) {
                        uStack_d8 = (ulong)iStack_8c;
                        cStack_c9 = uStack_d8 < 0xf;
                        uVar1 = (x.602 + -1) * x.602 & 1;
                        iVar4 = 0x4c8787c9;
                        if (9 < y.603 == uVar1 && (9 < y.603 | uVar1) == 1) {
                          iVar4 = -0x121d21a;
                        }
                      }
                      else if (iVar5 == -0x7654fd09) {
                        bVar3 = ((x.602 + -1) * x.602 & 1U) == 0;
                        iVar4 = 0x5afc86a2;
                        if ((y.603 >= 10 || !bVar3) && y.603 < 10 == bVar3) {
                          iVar4 = 0x71c66ad6;
                        }
                      }
                    }
                    else if (iVar5 == -0x72acc27c) {
                      bVar3 = ((x.602 + -1) * x.602 & 1U) == 0;
                      iVar4 = -0x42b0fe45;
                      if ((y.603 >= 10 || !bVar3) && y.603 < 10 == bVar3) {
                        iVar4 = 0x35ccd019;
                      }
                    }
                    else if (iVar5 == -0x66e5567d) {
                      uStack_128 = uStack_88;
                      iStack_134 = 5;
                      iVar4 = 0x2ef476a;
                    }
                  }
                  else if (iVar5 < -0x5afce1de) {
                    if (iVar5 == -0x654b1ecd) {
                      cStack_9d = iStack_74 == 5;
                      bVar3 = ((x.602 + -1) * x.602 & 1U) == 0;
                      iVar4 = -0x61e1248c;
                      if ((y.603 >= 10 || !bVar3) && y.603 < 10 == bVar3) {
                        iVar4 = 0x63b8117c;
                      }
                    }
                    else if (iVar5 == -0x61e1248c) {
                      uStack_108 = uStack_70;
                      iStack_10c = iStack_74;
                      iVar4 = 0x1837319c;
                      if (cStack_9d == '\0') {
                        iVar4 = 0x16bc74f;
                      }
                    }
                  }
                  else if (iVar5 == -0x5afce1de) {
                    iVar4 = -0x7654fd09;
                    if (cStack_a9 == '\0') {
                      iVar4 = -0x72acc27c;
                    }
                  }
                  else if (iVar5 == -0x58316e6a) {
                    iStack_9c = iStack_138;
                    uStack_98 = uStack_148;
                    uStack_e0 = (ulong)iStack_138;
                    iVar4 = -0x348464e;
                    if (0x36 < uStack_e0) {
                      iVar4 = 0x26e2c211;
                    }
                  }
                }
                else if (iVar5 < -0x1bec0569) {
                  if (iVar5 < -0x41c95482) {
                    if (iVar5 == -0x46ee5f92) {
                      snprintf(pcStack_f0,0x100,&DAT_0013f798,
                               *(undefined8 *)(pcStack_f8 + uStack_d8 * 8),
                               (&PTR_DAT_0013e840)[uStack_e0]);
                      __android_log_print(3,&DAT_001401c8,&DAT_001401d0,__name);
                      access(__name,0);
                      iVar4 = 0x604e53ea;
                    }
                    else if (iVar5 == -0x42b0fe45) {
                      uVar1 = (x.602 + -1) * x.602;
                      bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                      iVar4 = -0x27e8be04;
                      if ((y.603 >= 10 || !bVar3) && y.603 < 10 == bVar3) {
                        iVar4 = 0x35ccd019;
                      }
                    }
                  }
                  else if (iVar5 == -0x41c95482) {
                    pcStack_f8 = pcVar2 + -0x80;
                    pcStack_f0 = pcVar2 + -0x180;
                    *(undefined **)(pcVar2 + -0x58) = &DAT_00140090;
                    *(undefined **)(pcVar2 + -0x60) = &DAT_00140070;
                    *(undefined **)(pcVar2 + -0x48) = &DAT_001400d0;
                    *(undefined **)(pcVar2 + -0x50) = &DAT_001400b0;
                    *(undefined **)(pcVar2 + -0x18) = &DAT_00140170;
                    *(undefined **)(pcVar2 + -0x20) = &DAT_00140140;
                    *(undefined **)(pcVar2 + -0x10) = &DAT_001401a0;
                    *(undefined **)(pcVar2 + -0x38) = &DAT_00140030;
                    *(undefined8 **)(pcVar2 + -0x40) = &DAT_001400f0;
                    *(undefined **)(pcVar2 + -0x28) = &DAT_00140120;
                    *(undefined **)(pcVar2 + -0x30) = &DAT_00140100;
                    *(undefined8 **)(pcVar2 + -0x78) = &DAT_00140020;
                    *(undefined **)pcStack_f8 = &DAT_00140000;
                    *(undefined **)(pcVar2 + -0x68) = &DAT_00140050;
                    *(undefined **)(pcVar2 + -0x70) = &DAT_00140030;
                    bVar3 = ((x.602 + -1) * x.602 & 1U) == 0;
                    pcVar2 = pcStack_f0;
                    iVar4 = 0x5f4d5455;
                    pcStack_e8 = pcStack_f8;
                    if ((y.603 >= 10 || !bVar3) && y.603 < 10 == bVar3) {
                      iVar4 = 0x733dc80e;
                    }
                  }
                  else if (iVar5 == -0x27e8be04) {
                    iStack_100 = 0;
                    uStack_118 = uStack_88;
                    iVar4 = 0x35f6a028;
                  }
                }
                else if (iVar5 < -0x348464e) {
                  if (iVar5 == -0x1bec0569) {
                    iVar4 = -0x41c95482;
                    if (((bStack_fa & bStack_f9 | bStack_fa ^ bStack_f9) & 1) == 0) {
                      iVar4 = 0x733dc80e;
                    }
                  }
                  else if (iVar5 == -0x12514cf6) {
                    uStack_140 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_001051d1);
                    iVar4 = 0x3ea95b41;
                  }
                }
                else if (iVar5 == -0x348464e) {
                  iStack_11c = 0;
                  uStack_130 = uStack_98;
                  iVar4 = 0x351bff29;
                }
                else if (iVar5 == -0x121d21a) {
                  iVar4 = -0x7e5952e3;
                }
                else if (iVar5 == 0x16bc74f) {
                  iVar4 = -0x12514cf6;
                  if (iStack_10c != 2) {
                    iVar4 = 0x3ea95b41;
                  }
                  uStack_140 = uStack_108;
                }
              }
              if (0x3ea95b40 < iVar5) break;
              if (iVar5 < 0x26e2c211) {
                if (iVar5 < 0x1837319c) {
                  if (iVar5 == 0x2ef476a) {
                    iStack_74 = iStack_134;
                    uStack_70 = uStack_128;
                    uVar1 = (x.602 + -1) * x.602;
                    bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                    iVar4 = -0x654b1ecd;
                    if (y.603 < 10 == bVar3 && (9 < y.603 || !bVar3)) {
                      iVar4 = 0x63b8117c;
                    }
                  }
                  else if (iVar5 == 0xa56e60c) {
                    iStack_11c = iStack_8c + 1;
                    uStack_130 = uStack_80;
                    iVar4 = 0x351bff29;
                  }
                }
                else if (iVar5 == 0x1837319c) {
                  uStack_148 = uStack_70;
                  iStack_138 = iStack_9c + 1;
                  iVar4 = -0x58316e6a;
                }
                else if (iVar5 == 0x23501abb) {
                  uStack_118 = uStack_a8;
                  iStack_100 = 1;
                  iVar4 = 0x35f6a028;
                }
              }
              else if (iVar5 < 0x35ccd019) {
                if (iVar5 == 0x26e2c211) {
                  uStack_108 = uStack_98;
                  iStack_10c = 2;
                  iVar4 = 0x16bc74f;
                }
                else if (iVar5 == 0x351bff29) {
                  iStack_8c = iStack_11c;
                  uStack_88 = uStack_130;
                  uVar1 = (x.602 + -1) * x.602;
                  bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
                  iVar4 = -0x7e5952e3;
                  if (9 < y.603 == bVar3 && (9 < y.603 || bVar3)) {
                    iVar4 = -0x121d21a;
                  }
                }
              }
              else {
                iVar4 = -0x42b0fe45;
                if ((iVar5 != 0x35ccd019) && (iVar4 = iVar5, iVar5 == 0x35f6a028)) {
                  uStack_80 = uStack_118;
                  iStack_134 = iStack_100;
                  uStack_128 = uStack_118;
                  iVar4 = 0xa56e60c;
                  if (iStack_100 != 0) {
                    iVar4 = 0x2ef476a;
                  }
                }
              }
            }
            if (iVar5 < 0x604e53ea) break;
            if (iVar5 < 0x71c66ad6) {
              if (iVar5 == 0x604e53ea) {
                pcStack_c8 = pcStack_f0;
                pcStack_c0 = pcStack_f0;
                ppuStack_b8 = &PTR_DAT_0013e840 + uStack_e0;
                snprintf(pcStack_f0,0x100,&DAT_0013f798,*(undefined8 *)(pcStack_f8 + uStack_d8 * 8),
                         *ppuStack_b8);
                __android_log_print(3,&DAT_001401c8,&DAT_001401d0,pcStack_c0);
                iVar4 = access(pcStack_c0,0);
                cStack_a9 = iVar4 == 0;
                uVar1 = (x.602 + -1) * x.602 & 1;
                iVar4 = -0x5afce1de;
                if (9 < y.603 == uVar1 && (9 < y.603 | uVar1) == 1) {
                  iVar4 = -0x46ee5f92;
                }
              }
              else if (iVar5 == 0x63b8117c) {
                iVar4 = -0x654b1ecd;
              }
            }
            else if (iVar5 == 0x71c66ad6) {
              __android_log_print(3,&DAT_001401c8,&DAT_001401f0,pcStack_c0);
              (**(code **)(*param_1 + 0x538))(param_1,*ppuStack_b8);
              iVar4 = 0x5afc86a2;
            }
            else if (iVar5 == 0x733dc80e) {
              iVar4 = -0x41c95482;
            }
          }
          if (iVar5 < 0x5afc86a2) break;
          if (iVar5 == 0x5afc86a2) {
            __android_log_print(3,&DAT_001401c8,&DAT_001401f0,pcStack_c0);
            uStack_a8 = (**(code **)(*param_1 + 0x538))(param_1,*ppuStack_b8);
            uVar1 = (x.602 + -1) * x.602;
            bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
            iVar4 = 0x23501abb;
            if (9 < y.603 == bVar3 && (9 < y.603 || bVar3)) {
              iVar4 = 0x71c66ad6;
            }
          }
          else if (iVar5 == 0x5f4d5455) {
            iStack_138 = 0;
            iVar4 = -0x58316e6a;
          }
        }
        if (iVar5 != 0x4c8787c9) break;
        iVar4 = 0x5037dec0;
        if (cStack_c9 == '\0') {
          iVar4 = -0x66e5567d;
        }
      }
      if (iVar5 != 0x5037dec0) break;
      uVar1 = (x.602 + -1) * x.602;
      bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
      iVar4 = 0x604e53ea;
      if (9 < y.603 == bVar3 && (9 < y.603 || bVar3)) {
        iVar4 = -0x46ee5f92;
      }
    }
  } while (iVar5 != 0x3ea95b41);
  return uStack_140;
}

