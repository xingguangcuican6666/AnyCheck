
undefined8
Java_luna_safe_luna_MainActivity_callLunaversion
          (long *param_1,undefined8 param_2,undefined8 param_3)

{
  uint uVar1;
  int iVar2;
  bool bVar3;
  undefined8 uVar4;
  time_t tVar5;
  int iVar6;
  code *pcVar7;
  char acStack_500 [512];
  char acStack_300 [256];
  char acStack_200 [256];
  long lStack_100;
  long lStack_f8;
  char cStack_e9;
  long lStack_e8;
  long lStack_e0;
  char cStack_d1;
  long lStack_d0;
  char *pcStack_c8;
  char *pcStack_c0;
  long lStack_b8;
  char cStack_a9;
  long lStack_a8;
  long lStack_a0;
  char *pcStack_98;
  undefined8 uStack_90;
  char *pcStack_88;
  char *pcStack_80;
  long lStack_78;
  char cStack_69;
  
  lStack_100 = (**(code **)(*param_1 + 0xf8))();
  iVar2 = -0x68694d83;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          while( true ) {
            while( true ) {
              while (iVar6 = iVar2, iVar2 = iVar6, 0xb9401f4 < iVar6) {
                if (iVar6 < 0x5b7237df) {
                  if (iVar6 < 0x3fcb25da) {
                    if (iVar6 < 0x1e79220f) {
                      iVar2 = 0x45ca652;
                      if (iVar6 != 0xb9401f5) {
                        if (iVar6 == 0x13dcbfe6) {
                          (**(code **)(*param_1 + 0x568))(param_1,lStack_e8,0);
                          iVar2 = 0x3fcb25da;
                        }
                        else {
                          iVar2 = iVar6;
                          if (iVar6 == 0x1a71db7a) {
                            lStack_f8 = (**(code **)(*param_1 + 0x108))
                                                  (param_1,lStack_100,&DAT_0013f700,&DAT_0013f720);
                            cStack_e9 = lStack_f8 == 0;
                            bVar3 = ((x.568 + -1) * x.568 & 1U) == 0;
                            iVar2 = -0x7e8a3a15;
                            if ((y.569 >= 10 || !bVar3) && y.569 < 10 == bVar3) {
                              iVar2 = 0x509c8ef9;
                            }
                          }
                        }
                      }
                    }
                    else if (iVar6 < 0x3893b09e) {
                      if (iVar6 == 0x1e79220f) {
                        bVar3 = ((x.568 + -1) * x.568 & 1U) == 0;
                        iVar2 = 0x6b558a2c;
                        if ((y.569 >= 10 || !bVar3) && y.569 < 10 == bVar3) {
                          iVar2 = -0x7d943cad;
                        }
                      }
                      else if (iVar6 == 0x36aa42f6) {
                        uVar1 = (x.568 + -1) * x.568 & 1;
                        iVar2 = -0x28c1c859;
                        if (9 < y.569 == uVar1 && (9 < y.569 | uVar1) == 1) {
                          iVar2 = 0x7d6384d3;
                        }
                      }
                    }
                    else if (iVar6 == 0x3893b09e) {
                      uVar1 = (x.568 + -1) * x.568;
                      bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                      iVar2 = 0x3fcb25da;
                      if ((y.569 >= 10 || !bVar3) && y.569 < 10 == bVar3) {
                        iVar2 = 0x13dcbfe6;
                      }
                    }
                    else if (iVar6 == 0x3de20ba3) {
                      tVar5 = time((time_t *)0x0);
                      snprintf(acStack_200,0x100,&DAT_0013f738,lStack_d0,tVar5);
                      __android_log_print(4,&DAT_0013f18c,&DAT_0013f740,acStack_200);
                      (**(code **)(*param_1 + 0x108))
                                (param_1,lStack_100,&DAT_0013f750,&DAT_0013f760);
                      iVar2 = 0x6b4db6a7;
                    }
                  }
                  else if (iVar6 < 0x509c8ef9) {
                    if (iVar6 == 0x3fcb25da) {
                      lStack_e0 = (**(code **)(*param_1 + 0x568))(param_1,lStack_e8,0);
                      cStack_d1 = lStack_e0 == 0;
                      uVar1 = (x.568 + -1) * x.568;
                      bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                      iVar2 = -0x63f6fded;
                      if ((y.569 >= 10 || !bVar3) && y.569 < 10 == bVar3) {
                        iVar2 = 0x13dcbfe6;
                      }
                    }
                    else if (iVar6 == 0x4915c10e) {
                      lStack_a0 = (**(code **)(*param_1 + 0x548))(param_1,lStack_a8,0);
                      iVar2 = 0x724c3488;
                      if (lStack_a0 != 0) {
                        iVar2 = 0x5fd0e0bd;
                      }
                    }
                    else if (iVar6 == 0x498a098e) {
                      uVar1 = (x.568 + -1) * x.568 & 1;
                      iVar2 = 0x5a13f23d;
                      if (9 < y.569 == uVar1 && (9 < y.569 | uVar1) == 1) {
                        iVar2 = 0x21f9594;
                      }
                    }
                  }
                  else if (iVar6 < 0x57b15663) {
                    if (iVar6 == 0x509c8ef9) {
                      (**(code **)(*param_1 + 0x108))
                                (param_1,lStack_100,&DAT_0013f700,&DAT_0013f720);
                      iVar2 = 0x1a71db7a;
                    }
                    else if (iVar6 == 0x548ab1a5) {
                      iVar2 = -0x6959af4d;
                    }
                  }
                  else if (iVar6 == 0x57b15663) {
                    bVar3 = ((x.568 + -1) * x.568 & 1U) == 0;
                    iVar2 = 0x789bf335;
                    if ((y.569 >= 10 || !bVar3) && y.569 < 10 == bVar3) {
                      iVar2 = -0x2da85d13;
                    }
                  }
                  else if (iVar6 == 0x5a13f23d) {
                    pcVar7 = *(code **)(*param_1 + 0x1e8);
                    uVar4 = (**(code **)(*param_1 + 0x538))(param_1,pcStack_80);
                    (*pcVar7)(param_1,param_2,lStack_78,uVar4);
                    (**(code **)(*param_1 + 0x550))(param_1,lStack_e0,lStack_d0);
                    (**(code **)(*param_1 + 0x550))(param_1,lStack_a8,lStack_a0);
                    (**(code **)(*param_1 + 0x550))(param_1,param_3,uStack_90);
                    bVar3 = ((x.568 + -1) * x.568 & 1U) == 0;
                    iVar2 = 0xb9401f5;
                    if ((y.569 >= 10 || !bVar3) && y.569 < 10 == bVar3) {
                      iVar2 = 0x21f9594;
                    }
                  }
                }
                else if (iVar6 < 0x6d1ce273) {
                  if (iVar6 < 0x66dc61fe) {
                    iVar2 = -0x3b2964e1;
                    if (iVar6 != 0x5b7237df) {
                      if (iVar6 == 0x5b7e543b) {
                        snprintf(acStack_300,0x100,(char *)&DAT_0013f788,lStack_a0);
                        uVar4 = (**(code **)(*param_1 + 0x548))(param_1,param_3,0);
                        snprintf(acStack_500,0x200,&DAT_0013f798,uVar4,acStack_300);
                        (**(code **)(*param_1 + 0x108))
                                  (param_1,lStack_100,&DAT_0013f7a0,&DAT_0013f7c0);
                        iVar2 = -0x5ecb2b9e;
                      }
                      else {
                        iVar2 = iVar6;
                        if (iVar6 == 0x5fd0e0bd) {
                          uVar1 = (x.568 + -1) * x.568;
                          bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
                          iVar2 = -0x5ecb2b9e;
                          if (9 < y.569 == bVar3 && (9 < y.569 || bVar3)) {
                            iVar2 = 0x5b7e543b;
                          }
                        }
                      }
                    }
                  }
                  else if (iVar6 < 0x6b4db6a7) {
                    iVar2 = -0x37647fa7;
                    if ((iVar6 != 0x66dc61fe) && (iVar2 = iVar6, iVar6 == 0x66fb0a66)) {
                      iVar2 = -0x6959af4d;
                    }
                  }
                  else if (iVar6 == 0x6b4db6a7) {
                    tVar5 = time((time_t *)0x0);
                    pcStack_c8 = acStack_200;
                    pcStack_c0 = pcStack_c8;
                    snprintf(pcStack_c8,0x100,&DAT_0013f738,lStack_d0,tVar5);
                    __android_log_print(4,&DAT_0013f18c,&DAT_0013f740,pcStack_c0);
                    lStack_b8 = (**(code **)(*param_1 + 0x108))
                                          (param_1,lStack_100,&DAT_0013f750,&DAT_0013f760);
                    cStack_a9 = lStack_b8 == 0;
                    bVar3 = ((x.568 + -1) * x.568 & 1U) == 0;
                    iVar2 = 0x7414d3d7;
                    if ((y.569 >= 10 || !bVar3) && y.569 < 10 == bVar3) {
                      iVar2 = 0x3de20ba3;
                    }
                  }
                  else if (iVar6 == 0x6b558a2c) {
                    iVar2 = 0x57b15663;
                  }
                }
                else if (iVar6 < 0x77315182) {
                  if (iVar6 < 0x7414d3d7) {
                    iVar2 = -0x17613d9b;
                    if ((iVar6 != 0x6d1ce273) && (iVar2 = iVar6, iVar6 == 0x724c3488)) {
                      iVar2 = 0x5b7237df;
                    }
                  }
                  else if (iVar6 == 0x7414d3d7) {
                    iVar2 = -0x6700bb8a;
                    if (cStack_a9 == '\0') {
                      iVar2 = -0x4a8173e;
                    }
                  }
                  else if (iVar6 == 0x76631f12) {
                    lStack_d0 = (**(code **)(*param_1 + 0x548))(param_1,lStack_e0,0);
                    iVar2 = -0x1c2c0ae0;
                    if (lStack_d0 != 0) {
                      iVar2 = 0x77315182;
                    }
                  }
                }
                else if (iVar6 < 0x7ce383c0) {
                  if (iVar6 == 0x77315182) {
                    bVar3 = ((x.568 + -1) * x.568 & 1U) == 0;
                    iVar2 = 0x6b4db6a7;
                    if ((y.569 >= 10 || !bVar3) && y.569 < 10 == bVar3) {
                      iVar2 = 0x3de20ba3;
                    }
                  }
                  else if (iVar6 == 0x789bf335) {
                    uVar1 = (x.568 + -1) * x.568 & 1;
                    iVar2 = -0x7ff9d9d8;
                    if (9 < y.569 == uVar1 && (9 < y.569 | uVar1) == 1) {
                      iVar2 = -0x2da85d13;
                    }
                  }
                }
                else if (iVar6 == 0x7ce383c0) {
                  iVar2 = -0x5832dc16;
                  if (cStack_69 == '\0') {
                    iVar2 = 0x498a098e;
                  }
                }
                else if (iVar6 == 0x7d6384d3) {
                  iVar2 = 0x36aa42f6;
                }
              }
              if (iVar6 < -0x37647fa7) break;
              if (iVar6 < -0x1f3f7157) {
                if (iVar6 < -0x2da85d13) {
                  iVar2 = -0x17613d9b;
                  if (((iVar6 != -0x37647fa7) && (iVar2 = -0x3b2964e1, iVar6 != -0x35941f99)) &&
                     (iVar2 = iVar6, iVar6 == -0x2e8e2f43)) {
                    uVar1 = (x.568 + -1) * x.568;
                    bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                    iVar2 = 0x66dc61fe;
                    if (y.569 < 10 == bVar3 && (9 < y.569 || !bVar3)) {
                      iVar2 = -0x2c7d75cd;
                    }
                  }
                }
                else if (iVar6 < -0x28c1c859) {
                  iVar2 = 0x789bf335;
                  if ((iVar6 != -0x2da85d13) && (iVar2 = iVar6, iVar6 == -0x2c7d75cd)) {
                    iVar2 = -0x2e8e2f43;
                  }
                }
                else {
                  iVar2 = -0x1d0fd294;
                  if ((iVar6 != -0x28c1c859) && (iVar2 = iVar6, iVar6 == -0x25517890)) {
                    iVar2 = -0x5d275c16;
                  }
                }
              }
              else if (iVar6 < -0x17613d9b) {
                if (iVar6 == -0x1f3f7157) {
                  uVar1 = (x.568 + -1) * x.568;
                  bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                  iVar2 = 0x1a71db7a;
                  if ((y.569 >= 10 || !bVar3) && y.569 < 10 == bVar3) {
                    iVar2 = 0x509c8ef9;
                  }
                }
                else if (iVar6 == -0x1d0fd294) {
                  iVar2 = -0x37647fa7;
                }
                else if (iVar6 == -0x1c2c0ae0) {
                  bVar3 = ((x.568 + -1) * x.568 & 1U) == 0;
                  iVar2 = -0x2e8e2f43;
                  if ((y.569 >= 10 || !bVar3) && y.569 < 10 == bVar3) {
                    iVar2 = -0x2c7d75cd;
                  }
                }
              }
              else if (iVar6 < 0x21f9594) {
                iVar2 = 0x548ab1a5;
                if ((iVar6 != -0x17613d9b) && (iVar2 = iVar6, iVar6 == -0x4a8173e)) {
                  uVar4 = (**(code **)(*param_1 + 0x538))(param_1,pcStack_c0);
                  lStack_a8 = (**(code **)(*param_1 + 0x110))(param_1,param_2,lStack_b8,uVar4);
                  iVar2 = -0x35941f99;
                  if (lStack_a8 != 0) {
                    iVar2 = 0x4915c10e;
                  }
                }
              }
              else if (iVar6 == 0x21f9594) {
                pcVar7 = *(code **)(*param_1 + 0x1e8);
                uVar4 = (**(code **)(*param_1 + 0x538))(param_1,pcStack_80);
                (*pcVar7)(param_1,param_2,lStack_78,uVar4);
                (**(code **)(*param_1 + 0x550))(param_1,lStack_e0,lStack_d0);
                (**(code **)(*param_1 + 0x550))(param_1,lStack_a8,lStack_a0);
                (**(code **)(*param_1 + 0x550))(param_1,param_3,uStack_90);
                iVar2 = 0x5a13f23d;
              }
              else if (iVar6 == 0x45ca652) {
                iVar2 = 0x5b7237df;
              }
            }
            if (iVar6 < -0x63f6fded) break;
            if (iVar6 < -0x5d275c16) {
              if (iVar6 == -0x63f6fded) {
                iVar2 = 0x6d1ce273;
                if (cStack_d1 == '\0') {
                  iVar2 = 0x76631f12;
                }
              }
              else if (iVar6 == -0x5ecb2b9e) {
                pcStack_98 = acStack_300;
                snprintf(acStack_300,0x100,(char *)&DAT_0013f788,pcStack_98,lStack_a0);
                uStack_90 = (**(code **)(*param_1 + 0x548))(param_1,param_3,0);
                pcStack_88 = acStack_500;
                pcStack_80 = pcStack_88;
                snprintf(pcStack_88,0x200,&DAT_0013f798,pcStack_88,uStack_90,acStack_300);
                lStack_78 = (**(code **)(*param_1 + 0x108))
                                      (param_1,lStack_100,&DAT_0013f7a0,&DAT_0013f7c0);
                cStack_69 = lStack_78 == 0;
                bVar3 = ((x.568 + -1) * x.568 & 1U) == 0;
                iVar2 = 0x7ce383c0;
                if ((y.569 >= 10 || !bVar3) && y.569 < 10 == bVar3) {
                  iVar2 = 0x5b7e543b;
                }
              }
              else if (iVar6 == -0x5ec449c6) {
                iVar2 = 0x548ab1a5;
              }
            }
            else if (iVar6 < -0x45e6e09e) {
              if (iVar6 == -0x5d275c16) {
                uVar1 = (x.568 + -1) * x.568;
                bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                iVar2 = 0x66fb0a66;
                if (y.569 < 10 == bVar3 && (9 < y.569 || !bVar3)) {
                  iVar2 = -0x25517890;
                }
              }
              else if (iVar6 == -0x5832dc16) {
                iVar2 = 0x45ca652;
              }
            }
            else if (iVar6 == -0x45e6e09e) {
              bVar3 = ((x.568 + -1) * x.568 & 1U) == 0;
              iVar2 = -0x5d275c16;
              if ((y.569 >= 10 || !bVar3) && y.569 < 10 == bVar3) {
                iVar2 = -0x25517890;
              }
            }
            else if (iVar6 == -0x3b2964e1) {
              uVar1 = (x.568 + -1) * x.568 & 1;
              iVar2 = 0x36aa42f6;
              if (y.569 < 10 == (uVar1 == 0) && (9 < y.569 | uVar1) == 1) {
                iVar2 = 0x7d6384d3;
              }
            }
          }
          if (iVar6 < -0x76f3e866) break;
          if (iVar6 < -0x68694d83) {
            if (iVar6 == -0x76f3e866) {
              uVar1 = (x.568 + -1) * x.568;
              bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
              iVar2 = 0x1e79220f;
              if ((y.569 >= 10 || !bVar3) && y.569 < 10 == bVar3) {
                iVar2 = -0x7d943cad;
              }
            }
            else if (iVar6 == -0x6959af4d) {
              iVar2 = 0x57b15663;
            }
          }
          else if (iVar6 == -0x68694d83) {
            iVar2 = -0x76f3e866;
            if (lStack_100 != 0) {
              iVar2 = -0x1f3f7157;
            }
          }
          else if (iVar6 == -0x6700bb8a) {
            iVar2 = -0x1d0fd294;
          }
        }
        if (iVar6 < -0x7d943cad) break;
        iVar2 = 0x1e79220f;
        if ((iVar6 != -0x7d943cad) && (iVar2 = iVar6, iVar6 == -0x7bfcf4fa)) {
          lStack_e8 = (**(code **)(*param_1 + 0x110))(param_1,param_2,lStack_f8);
          iVar2 = -0x5ec449c6;
          if (lStack_e8 != 0) {
            iVar2 = 0x3893b09e;
          }
        }
      }
      if (iVar6 != -0x7e8a3a15) break;
      iVar2 = -0x45e6e09e;
      if (cStack_e9 == '\0') {
        iVar2 = -0x7bfcf4fa;
      }
    }
  } while (iVar6 != -0x7ff9d9d8);
  return 0;
}

