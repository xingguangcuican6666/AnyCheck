
undefined8
Java_luna_safe_luna_MainActivity_kernels(long *param_1,undefined8 param_2,undefined8 param_3)

{
  uint uVar1;
  char *pcVar2;
  int iVar3;
  bool bVar4;
  time_t tVar5;
  undefined8 uVar6;
  char *pcVar7;
  int iVar8;
  code *pcVar9;
  undefined1 auStack_130 [8];
  undefined8 local_128;
  undefined8 local_120;
  byte local_112;
  byte local_111;
  char *local_110;
  char *local_108;
  char *local_100;
  long local_f8;
  char local_e9;
  long local_e8;
  long local_e0;
  char local_d1;
  long local_d0;
  long local_c8;
  char *local_c0;
  char *local_b8;
  long local_b0;
  char local_a1;
  long local_a0;
  long local_98;
  char *local_90;
  undefined8 local_88;
  char *local_80;
  char *local_78;
  long local_70;
  
  pcVar7 = auStack_130;
  uVar1 = (x.580 + -1) * x.580;
  local_112 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
  local_111 = y.581 < 10;
  iVar3 = -0x1e6ef871;
  local_128 = param_3;
  local_120 = param_2;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          while( true ) {
            while (iVar8 = iVar3, pcVar2 = local_108, iVar3 = iVar8, iVar8 < -0x91cd52b) {
              if (iVar8 < -0x54552652) {
                if (iVar8 < -0x658d264a) {
                  if (iVar8 < -0x6d71233a) {
                    if (iVar8 < -0x710f7b70) {
                      if (iVar8 == -0x79506db5) {
                        uVar1 = (x.580 + -1) * x.580 & 1;
                        iVar3 = -0x3fa77ea5;
                        if (9 < y.581 == uVar1 && (9 < y.581 | uVar1) == 1) {
                          iVar3 = 0x69f6cce0;
                        }
                      }
                      else if (iVar8 == -0x76b6580f) {
                        uVar1 = (x.580 + -1) * x.580 & 1;
                        iVar3 = 0x4ba6376b;
                        if (9 < y.581 == uVar1 && (9 < y.581 | uVar1) == 1) {
                          iVar3 = 0x5d5d992b;
                        }
                      }
                    }
                    else if (iVar8 == -0x710f7b70) {
                      uVar1 = (x.580 + -1) * x.580;
                      bVar4 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
                      iVar3 = -0x56cba66d;
                      if (9 < y.581 == bVar4 && (9 < y.581 || bVar4)) {
                        iVar3 = 0x7a0fc3ec;
                      }
                    }
                    else if (iVar8 == -0x6f6acad2) {
                      iVar3 = -0x15a7449b;
                    }
                  }
                  else if (iVar8 < -0x6668e30a) {
                    if (iVar8 == -0x6d71233a) {
                      uVar1 = (x.580 + -1) * x.580 & 1;
                      iVar3 = -0x76b6580f;
                      if (y.581 < 10 == (uVar1 == 0) && (9 < y.581 | uVar1) == 1) {
                        iVar3 = 0x5d5d992b;
                      }
                    }
                    else if (iVar8 == -0x68f5730d) {
                      local_e8 = (**(code **)(*param_1 + 0x108))
                                           (param_1,local_f8,&DAT_0013f700,&DAT_0013f720);
                      iVar3 = -0x26d6b076;
                      if (local_e8 != 0) {
                        iVar3 = 0x407f72f9;
                      }
                    }
                  }
                  else if (iVar8 == -0x6668e30a) {
                    uVar6 = (**(code **)(*param_1 + 0x538))(param_1,local_b8);
                    local_a0 = (**(code **)(*param_1 + 0x110))(param_1,local_120,local_b0,uVar6);
                    iVar3 = 0x4f0b8820;
                    if (local_a0 != 0) {
                      iVar3 = 0x44b1e7b8;
                    }
                  }
                  else if (iVar8 == -0x6591c666) {
                    (**(code **)(*param_1 + 0xf8))(param_1,local_120);
                    iVar3 = 0x5ab04ea0;
                  }
                }
                else if (iVar8 < -0x5ac9815f) {
                  if (iVar8 < -0x5fd912dc) {
                    iVar3 = 0x2e411f82;
                    if ((iVar8 != -0x658d264a) && (iVar3 = iVar8, iVar8 == -0x6446ca8c)) {
                      iVar3 = -0x2292233f;
                    }
                  }
                  else if (iVar8 == -0x5fd912dc) {
                    iVar3 = 0x2e411f82;
                  }
                  else if (iVar8 == -0x5b0f4700) {
                    iVar3 = -0x91cd52b;
                  }
                }
                else if (iVar8 < -0x56cba66d) {
                  if (iVar8 == -0x5ac9815f) {
                    tVar5 = time((time_t *)0x0);
                    snprintf(local_110,0x100,&DAT_0013f870,local_c8,tVar5);
                    (**(code **)(*param_1 + 0x108))(param_1,local_f8,&DAT_0013f750,&DAT_0013f760);
                    iVar3 = 0x56802161;
                  }
                  else if (iVar8 == -0x597d19eb) {
                    iVar3 = -0x5fd912dc;
                  }
                }
                else if (iVar8 == -0x56cba66d) {
                  uVar1 = (x.580 + -1) * x.580;
                  bVar4 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
                  iVar3 = 0xb803c57;
                  if (9 < y.581 == bVar4 && (9 < y.581 || bVar4)) {
                    iVar3 = 0x7a0fc3ec;
                  }
                }
                else if (iVar8 == -0x55bf98e1) {
                  iVar3 = 0x332a0902;
                }
              }
              else if (iVar8 < -0x26d6b076) {
                if (iVar8 < -0x3fa77ea5) {
                  if (iVar8 < -0x498883fa) {
                    if (iVar8 == -0x54552652) {
                      local_e0 = (**(code **)(*param_1 + 0x110))(param_1,local_120,local_e8);
                      local_d1 = local_e0 == 0;
                      bVar4 = ((x.580 + -1) * x.580 & 1U) == 0;
                      iVar3 = -0x2811abd4;
                      if ((y.581 >= 10 || !bVar4) && y.581 < 10 == bVar4) {
                        iVar3 = 0x29b60bcd;
                      }
                    }
                    else if (iVar8 == -0x4b5838ee) {
                      uVar1 = (x.580 + -1) * x.580;
                      bVar4 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                      iVar3 = -0x21c7cd12;
                      if ((y.581 >= 10 || !bVar4) && y.581 < 10 == bVar4) {
                        iVar3 = 0x3ee83dbf;
                      }
                    }
                  }
                  else {
                    iVar3 = -0x597d19eb;
                    if ((iVar8 != -0x498883fa) && (iVar3 = iVar8, iVar8 == -0x40879031)) {
                      iVar3 = 0x188e5cd2;
                    }
                  }
                }
                else if (iVar8 < -0x332be6f5) {
                  if (iVar8 == -0x3fa77ea5) {
                    uVar1 = (x.580 + -1) * x.580;
                    bVar4 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                    iVar3 = -0x498883fa;
                    if ((y.581 >= 10 || !bVar4) && y.581 < 10 == bVar4) {
                      iVar3 = 0x69f6cce0;
                    }
                  }
                  else if (iVar8 == -0x34f9ac32) {
                    local_d0 = (**(code **)(*param_1 + 0x568))(param_1,local_e0,0);
                    iVar3 = 0x1b886e75;
                    if (local_d0 != 0) {
                      iVar3 = -0x2660ab3c;
                    }
                  }
                }
                else {
                  iVar3 = -0x7f9d267;
                  if ((iVar8 != -0x332be6f5) && (iVar3 = iVar8, iVar8 == -0x2811abd4)) {
                    iVar3 = 0x123a88f7;
                    if (local_d1 == '\0') {
                      iVar3 = -0x34f9ac32;
                    }
                  }
                }
              }
              else if (iVar8 < -0x1e6ef871) {
                if (iVar8 < -0x2292233f) {
                  iVar3 = -0x710f7b70;
                  if ((iVar8 != -0x26d6b076) && (iVar3 = iVar8, iVar8 == -0x2660ab3c)) {
                    local_c8 = (**(code **)(*param_1 + 0x548))(param_1,local_d0,0);
                    iVar3 = -0x658d264a;
                    if (local_c8 != 0) {
                      iVar3 = 0x3a0053ef;
                    }
                  }
                }
                else if (iVar8 == -0x2292233f) {
                  uVar1 = (x.580 + -1) * x.580;
                  bVar4 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
                  iVar3 = -0x4b5838ee;
                  if (9 < y.581 == bVar4 && (9 < y.581 || bVar4)) {
                    iVar3 = 0x3ee83dbf;
                  }
                }
                else if (iVar8 == -0x21c7cd12) {
                  iVar3 = -0x79506db5;
                }
              }
              else if (iVar8 < -0x15a7449b) {
                if (iVar8 == -0x1e6ef871) {
                  iVar3 = 0x5ab04ea0;
                  if (((local_112 & local_111 | local_112 ^ local_111) & 1) == 0) {
                    iVar3 = -0x6591c666;
                  }
                }
                else if (iVar8 == -0x192bfc7d) {
                  uVar1 = (x.580 + -1) * x.580;
                  bVar4 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                  iVar3 = 0x3aa79464;
                  if ((y.581 >= 10 || !bVar4) && y.581 < 10 == bVar4) {
                    iVar3 = 0x16c4f5;
                  }
                }
              }
              else if (iVar8 == -0x15a7449b) {
                bVar4 = ((x.580 + -1) * x.580 & 1U) == 0;
                iVar3 = 0x339130af;
                if ((y.581 >= 10 || !bVar4) && y.581 < 10 == bVar4) {
                  iVar3 = -0x6f6acad2;
                }
              }
              else if (iVar8 == -0x1318654d) {
                pcVar9 = *(code **)(*param_1 + 0x1e8);
                uVar6 = (**(code **)(*param_1 + 0x538))(param_1,local_78);
                (*pcVar9)(param_1,local_120,local_70,uVar6);
                (**(code **)(*param_1 + 0x550))(param_1,local_d0,local_c8);
                (**(code **)(*param_1 + 0x550))(param_1,local_a0,local_98);
                (**(code **)(*param_1 + 0x550))(param_1,local_128,local_88);
                iVar3 = -0x7c1b3a9;
              }
            }
            if (0x3c5b6fd5 < iVar8) break;
            if (iVar8 < 0x188e5cd2) {
              if (iVar8 < 0x794d464) {
                if (iVar8 < -0x7c1b3a9) {
                  if (iVar8 == -0x91cd52b) {
                    uVar1 = (x.580 + -1) * x.580 & 1;
                    iVar3 = 0x188e5cd2;
                    if (y.581 < 10 == (uVar1 == 0) && (9 < y.581 | uVar1) == 1) {
                      iVar3 = -0x40879031;
                    }
                  }
                  else if (iVar8 == -0x7f9d267) {
                    bVar4 = ((x.580 + -1) * x.580 & 1U) == 0;
                    iVar3 = 0x746ef908;
                    if ((y.581 >= 10 || !bVar4) && y.581 < 10 == bVar4) {
                      iVar3 = -0x332be6f5;
                    }
                  }
                }
                else if (iVar8 == -0x7c1b3a9) {
                  pcVar9 = *(code **)(*param_1 + 0x1e8);
                  uVar6 = (**(code **)(*param_1 + 0x538))(param_1,local_78);
                  (*pcVar9)(param_1,local_120,local_70,uVar6);
                  (**(code **)(*param_1 + 0x550))(param_1,local_d0,local_c8);
                  (**(code **)(*param_1 + 0x550))(param_1,local_a0,local_98);
                  (**(code **)(*param_1 + 0x550))(param_1,local_128,local_88);
                  uVar1 = (x.580 + -1) * x.580 & 1;
                  iVar3 = -0x6446ca8c;
                  if (y.581 < 10 == (uVar1 == 0) && (9 < y.581 | uVar1) == 1) {
                    iVar3 = -0x1318654d;
                  }
                }
                else if (iVar8 == 0x16c4f5) {
                  iVar3 = 0x3aa79464;
                }
              }
              else if (iVar8 < 0xb803c57) {
                if (iVar8 == 0x794d464) {
                  iVar3 = -0x5b0f4700;
                  if (local_e9 == '\0') {
                    iVar3 = -0x68f5730d;
                  }
                }
                else if (iVar8 == 0xa4dadfc) {
                  iVar3 = -0x5fd912dc;
                }
              }
              else {
                iVar3 = -0x91cd52b;
                if ((iVar8 != 0xb803c57) && (iVar3 = iVar8, iVar8 == 0x123a88f7)) {
                  iVar3 = 0x332a0902;
                }
              }
            }
            else if (iVar8 < 0x332a0902) {
              if (iVar8 < 0x29b60bcd) {
                if (iVar8 == 0x188e5cd2) {
                  bVar4 = ((x.580 + -1) * x.580 & 1U) == 0;
                  iVar3 = 0x633fdf9e;
                  if ((y.581 >= 10 || !bVar4) && y.581 < 10 == bVar4) {
                    iVar3 = -0x40879031;
                  }
                }
                else if (iVar8 == 0x1b886e75) {
                  iVar3 = -0x55bf98e1;
                }
              }
              else if (iVar8 == 0x29b60bcd) {
                (**(code **)(*param_1 + 0x110))(param_1,local_120,local_e8);
                iVar3 = -0x54552652;
              }
              else if (iVar8 == 0x2e411f82) {
                uVar1 = (x.580 + -1) * x.580;
                bVar4 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
                iVar3 = -0x15a7449b;
                if (9 < y.581 == bVar4 && (9 < y.581 || bVar4)) {
                  iVar3 = -0x6f6acad2;
                }
              }
            }
            else if (iVar8 < 0x3a0053ef) {
              iVar3 = -0x710f7b70;
              if ((iVar8 != 0x332a0902) && (iVar3 = iVar8, iVar8 == 0x339130af)) {
                iVar3 = -0x55bf98e1;
              }
            }
            else if (iVar8 == 0x3a0053ef) {
              bVar4 = ((x.580 + -1) * x.580 & 1U) == 0;
              iVar3 = 0x56802161;
              if ((y.581 >= 10 || !bVar4) && y.581 < 10 == bVar4) {
                iVar3 = -0x5ac9815f;
              }
            }
            else if (iVar8 == 0x3aa79464) {
              uVar1 = (x.580 + -1) * x.580 & 1;
              iVar3 = 0x435f4d0f;
              if (9 < y.581 == uVar1 && (9 < y.581 | uVar1) == 1) {
                iVar3 = 0x16c4f5;
              }
            }
          }
          if (0x56802160 < iVar8) break;
          if (iVar8 < 0x44b1e7b8) {
            if (iVar8 < 0x407f72f9) {
              if (iVar8 == 0x3c5b6fd6) {
                iVar3 = 0xa4dadfc;
                if (local_a1 == '\0') {
                  iVar3 = -0x6668e30a;
                }
              }
              else if (iVar8 == 0x3ee83dbf) {
                iVar3 = -0x4b5838ee;
              }
            }
            else if (iVar8 == 0x407f72f9) {
              bVar4 = ((x.580 + -1) * x.580 & 1U) == 0;
              iVar3 = -0x54552652;
              if ((y.581 >= 10 || !bVar4) && y.581 < 10 == bVar4) {
                iVar3 = 0x29b60bcd;
              }
            }
            else if (iVar8 == 0x435f4d0f) {
              iVar3 = -0x79506db5;
            }
          }
          else if (iVar8 < 0x4ba6376b) {
            if (iVar8 == 0x44b1e7b8) {
              local_98 = (**(code **)(*param_1 + 0x548))(param_1,local_a0,0);
              iVar3 = -0x192bfc7d;
              if (local_98 != 0) {
                iVar3 = 0x5a748b2e;
              }
            }
            else if (iVar8 == 0x45e38a24) {
              bVar4 = ((x.580 + -1) * x.580 & 1U) == 0;
              iVar3 = -0x7c1b3a9;
              if ((y.581 >= 10 || !bVar4) && y.581 < 10 == bVar4) {
                iVar3 = -0x1318654d;
              }
            }
          }
          else {
            iVar3 = -0x2292233f;
            if ((iVar8 != 0x4ba6376b) && (iVar3 = iVar8, iVar8 == 0x4f0b8820)) {
              uVar1 = (x.580 + -1) * x.580 & 1;
              iVar3 = -0x7f9d267;
              if (9 < y.581 == uVar1 && (9 < y.581 | uVar1) == 1) {
                iVar3 = -0x332be6f5;
              }
            }
          }
        }
        if (0x633fdf9d < iVar8) break;
        if (iVar8 < 0x5ab04ea0) {
          if (iVar8 == 0x56802161) {
            tVar5 = time((time_t *)0x0);
            local_c0 = local_110;
            local_b8 = local_110;
            snprintf(local_110,0x100,&DAT_0013f870,local_c8,tVar5);
            local_b0 = (**(code **)(*param_1 + 0x108))(param_1,local_f8,&DAT_0013f750,&DAT_0013f760)
            ;
            local_a1 = local_b0 == 0;
            uVar1 = (x.580 + -1) * x.580;
            bVar4 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
            iVar3 = 0x3c5b6fd6;
            if ((y.581 >= 10 || !bVar4) && y.581 < 10 == bVar4) {
              iVar3 = -0x5ac9815f;
            }
          }
          else if (iVar8 == 0x5a748b2e) {
            local_90 = local_108;
            snprintf(local_108,0x100,(char *)&DAT_0013f7f8,local_98);
            local_88 = (**(code **)(*param_1 + 0x548))(param_1,local_128,0);
            local_80 = local_100;
            local_78 = local_100;
            snprintf(local_100,0x200,&DAT_0013f798,local_88,pcVar2);
            local_70 = (**(code **)(*param_1 + 0x108))(param_1,local_f8,&DAT_0013f7a0,&DAT_0013f7c0)
            ;
            iVar3 = -0x6d71233a;
            if (local_70 != 0) {
              iVar3 = 0x45e38a24;
            }
          }
        }
        else if (iVar8 == 0x5ab04ea0) {
          local_110 = pcVar7 + -0x100;
          local_108 = pcVar7 + -0x200;
          pcVar7 = pcVar7 + -0x400;
          local_100 = pcVar7;
          local_f8 = (**(code **)(*param_1 + 0xf8))(param_1,local_120);
          local_e9 = local_f8 == 0;
          uVar1 = (x.580 + -1) * x.580 & 1;
          iVar3 = 0x794d464;
          if (y.581 < 10 == (uVar1 == 0) && (9 < y.581 | uVar1) == 1) {
            iVar3 = -0x6591c666;
          }
        }
        else if (iVar8 == 0x5d5d992b) {
          iVar3 = -0x76b6580f;
        }
      }
      if (iVar8 < 0x746ef908) break;
      iVar3 = -0x597d19eb;
      if ((iVar8 != 0x746ef908) && (iVar3 = iVar8, iVar8 == 0x7a0fc3ec)) {
        iVar3 = -0x56cba66d;
      }
    }
    iVar3 = -0x3fa77ea5;
  } while ((iVar8 == 0x69f6cce0) || (iVar3 = iVar8, iVar8 != 0x633fdf9e));
  return 0;
}

