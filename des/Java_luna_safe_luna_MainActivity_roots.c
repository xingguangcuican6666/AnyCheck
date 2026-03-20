
undefined8
Java_luna_safe_luna_MainActivity_roots(long *param_1,undefined8 param_2,undefined8 param_3)

{
  uint uVar1;
  int iVar2;
  bool bVar3;
  time_t tVar4;
  undefined8 uVar5;
  int iVar6;
  code *pcVar7;
  char acStack_4f0 [512];
  char acStack_2f0 [256];
  char acStack_1f0 [256];
  long local_f0;
  long local_e8;
  long local_e0;
  char local_d1;
  long local_d0;
  long local_c8;
  char *local_c0;
  char *local_b8;
  long local_b0;
  long local_a8;
  char local_99;
  long local_98;
  char *local_90;
  undefined8 local_88;
  undefined1 *local_80;
  undefined1 *local_78;
  long local_70;
  
  local_f0 = (**(code **)(*param_1 + 0xf8))();
  iVar2 = 0x1a51bd80;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          while( true ) {
            while (iVar6 = iVar2, iVar2 = iVar6, iVar6 < 0x1a51bd80) {
              if (iVar6 < -0x30ccddca) {
                if (iVar6 < -0x3f12061e) {
                  if (iVar6 < -0x644dffe7) {
                    iVar2 = -0x3555e77f;
                    if (iVar6 != -0x78ebf6d2) {
                      if (iVar6 == -0x77ce107a) {
                        local_d0 = (**(code **)(*param_1 + 0x568))(param_1,local_e0,0);
                        iVar2 = 0x252128c1;
                        if (local_d0 != 0) {
                          iVar2 = 0x4ba5f8e1;
                        }
                      }
                      else {
                        iVar2 = iVar6;
                        if (iVar6 == -0x70b14076) {
                          local_90 = acStack_2f0;
                          snprintf(acStack_2f0,0x100,(char *)&DAT_0013f7f8,local_90,local_98);
                          local_88 = (**(code **)(*param_1 + 0x548))(param_1,param_3,0);
                          local_80 = acStack_4f0;
                          local_78 = acStack_4f0;
                          snprintf(acStack_4f0,0x200,&DAT_0013f798,acStack_4f0,local_88,acStack_2f0)
                          ;
                          __android_log_print(4,&DAT_0013f18c,&DAT_0013f850,local_78);
                          local_70 = (**(code **)(*param_1 + 0x108))
                                               (param_1,local_f0,&DAT_0013f7a0,&DAT_0013f7c0);
                          iVar2 = 0x32e5869;
                          if (local_70 != 0) {
                            iVar2 = -0x1a18079d;
                          }
                        }
                      }
                    }
                  }
                  else if (iVar6 < -0x4fbf03dc) {
                    if (iVar6 == -0x644dffe7) {
                      (**(code **)(*param_1 + 0x110))(param_1,param_2,local_e8);
                      iVar2 = -0x2c7661aa;
                    }
                    else if (iVar6 == -0x57655c6f) {
                      iVar2 = 0x29ed482b;
                    }
                  }
                  else if (iVar6 == -0x4fbf03dc) {
                    uVar1 = (x.578 + -1) * x.578;
                    bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                    iVar2 = -0x1ea2878a;
                    if ((y.579 >= 10 || !bVar3) && y.579 < 10 == bVar3) {
                      iVar2 = -0x24c4fe7a;
                    }
                  }
                  else if (iVar6 == -0x3feb1463) {
                    iVar2 = 0x3b872c59;
                  }
                }
                else if (iVar6 < -0x3a10abf6) {
                  iVar2 = 0x38a91317;
                  if (((iVar6 != -0x3f12061e) && (iVar2 = -0x230daf6e, iVar6 != -0x3ec9bddc)) &&
                     (iVar2 = iVar6, iVar6 == -0x3a8731cd)) {
                    uVar1 = (x.578 + -1) * x.578;
                    bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                    iVar2 = 0x5581e668;
                    if (y.579 < 10 == bVar3 && (9 < y.579 || !bVar3)) {
                      iVar2 = 0x244953a9;
                    }
                  }
                }
                else if (iVar6 < -0x3555e77f) {
                  if (iVar6 == -0x3a10abf6) {
                    iVar2 = 0x66185962;
                    if (local_d1 == '\0') {
                      iVar2 = -0x77ce107a;
                    }
                  }
                  else if (iVar6 == -0x3796b8ba) {
                    iVar2 = 0x56fed721;
                  }
                }
                else if (iVar6 == -0x3555e77f) {
                  uVar1 = (x.578 + -1) * x.578 & 1;
                  iVar2 = 0x2ef88766;
                  if (9 < y.579 == uVar1 && (9 < y.579 | uVar1) == 1) {
                    iVar2 = -0x1ad44282;
                  }
                }
                else if (iVar6 == -0x33aa9ed1) {
                  iVar2 = -0x4fbf03dc;
                }
              }
              else if (iVar6 < -0x1828c2c6) {
                if (iVar6 < -0x230daf6e) {
                  if (iVar6 == -0x30ccddca) {
                    uVar1 = (x.578 + -1) * x.578 & 1;
                    iVar2 = -0x78ebf6d2;
                    if (y.579 < 10 == (uVar1 == 0) && (9 < y.579 | uVar1) == 1) {
                      iVar2 = 0x37f9a2c1;
                    }
                  }
                  else if (iVar6 == -0x2c7661aa) {
                    local_e0 = (**(code **)(*param_1 + 0x110))(param_1,param_2,local_e8);
                    local_d1 = local_e0 == 0;
                    bVar3 = ((x.578 + -1) * x.578 & 1U) == 0;
                    iVar2 = -0x3a10abf6;
                    if ((y.579 >= 10 || !bVar3) && y.579 < 10 == bVar3) {
                      iVar2 = -0x644dffe7;
                    }
                  }
                  else if (iVar6 == -0x24c4fe7a) {
                    iVar2 = -0x1ea2878a;
                  }
                }
                else if (iVar6 < -0x1ad44282) {
                  if (iVar6 == -0x230daf6e) {
                    uVar1 = (x.578 + -1) * x.578 & 1;
                    iVar2 = 0x2e12685c;
                    if (y.579 < 10 == (uVar1 == 0) && (9 < y.579 | uVar1) == 1) {
                      iVar2 = -0x3ec9bddc;
                    }
                  }
                  else if (iVar6 == -0x1ea2878a) {
                    uVar1 = (x.578 + -1) * x.578;
                    bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
                    iVar2 = -0x3f12061e;
                    if (9 < y.579 == bVar3 && (9 < y.579 || bVar3)) {
                      iVar2 = -0x24c4fe7a;
                    }
                  }
                }
                else {
                  iVar2 = 0x2ef88766;
                  if ((iVar6 != -0x1ad44282) && (iVar2 = iVar6, iVar6 == -0x1a18079d)) {
                    pcVar7 = *(code **)(*param_1 + 0x1e8);
                    uVar5 = (**(code **)(*param_1 + 0x538))(param_1,local_78);
                    (*pcVar7)(param_1,param_2,local_70,uVar5);
                    (**(code **)(*param_1 + 0x550))(param_1,local_d0,local_c8);
                    (**(code **)(*param_1 + 0x550))(param_1,local_a8,local_98);
                    (**(code **)(*param_1 + 0x550))(param_1,param_3,local_88);
                    iVar2 = -0x3555e77f;
                  }
                }
              }
              else if (iVar6 < 0x32e5869) {
                if (iVar6 < -0xbfe8746) {
                  iVar2 = 0x6c97afca;
                  if ((iVar6 != -0x1828c2c6) && (iVar2 = iVar6, iVar6 == -0xcebe43c)) {
                    tVar4 = time((time_t *)0x0);
                    local_c0 = acStack_1f0;
                    local_b8 = local_c0;
                    snprintf(local_c0,0x100,&DAT_0013f830,local_c8,tVar4);
                    local_b0 = (**(code **)(*param_1 + 0x108))
                                         (param_1,local_f0,&DAT_0013f750,&DAT_0013f760);
                    iVar2 = 0x6bc3c63f;
                    if (local_b0 != 0) {
                      iVar2 = 0x7df5ff39;
                    }
                  }
                }
                else {
                  iVar2 = 0x25109070;
                  if ((iVar6 != -0xbfe8746) && (iVar2 = iVar6, iVar6 == 0xefe6fa)) {
                    uVar5 = (**(code **)(*param_1 + 0x538))(param_1,local_b8);
                    (**(code **)(*param_1 + 0x110))(param_1,param_2,local_b0,uVar5);
                    iVar2 = 0xb4cb5e8;
                  }
                }
              }
              else if (iVar6 < 0xc570878) {
                if (iVar6 == 0x32e5869) {
                  uVar1 = (x.578 + -1) * x.578;
                  bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
                  iVar2 = -0x30ccddca;
                  if (9 < y.579 == bVar3 && (9 < y.579 || bVar3)) {
                    iVar2 = 0x37f9a2c1;
                  }
                }
                else if (iVar6 == 0xb4cb5e8) {
                  uVar5 = (**(code **)(*param_1 + 0x538))(param_1,local_b8);
                  local_a8 = (**(code **)(*param_1 + 0x110))(param_1,param_2,local_b0,uVar5);
                  local_99 = local_a8 == 0;
                  bVar3 = ((x.578 + -1) * x.578 & 1U) == 0;
                  iVar2 = 0x376c6ad7;
                  if ((y.579 >= 10 || !bVar3) && y.579 < 10 == bVar3) {
                    iVar2 = 0xefe6fa;
                  }
                }
              }
              else if (iVar6 == 0xc570878) {
                bVar3 = ((x.578 + -1) * x.578 & 1U) == 0;
                iVar2 = -0x2c7661aa;
                if ((y.579 >= 10 || !bVar3) && y.579 < 10 == bVar3) {
                  iVar2 = -0x644dffe7;
                }
              }
              else if (iVar6 == 0xf58d677) {
                iVar2 = -0x57655c6f;
              }
            }
            if (0x524a9c3a < iVar6) break;
            if (iVar6 < 0x376c6ad7) {
              if (iVar6 < 0x252128c1) {
                if (iVar6 == 0x1a51bd80) {
                  iVar2 = 0x5b3141f8;
                  if (local_f0 != 0) {
                    iVar2 = 0x5d24df2a;
                  }
                }
                else {
                  iVar2 = -0x3a8731cd;
                  if ((iVar6 != 0x244953a9) && (iVar2 = iVar6, iVar6 == 0x25109070)) {
                    uVar1 = (x.578 + -1) * x.578;
                    bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                    iVar2 = 0x6ffda744;
                    if ((y.579 >= 10 || !bVar3) && y.579 < 10 == bVar3) {
                      iVar2 = 0x51f36c43;
                    }
                  }
                }
              }
              else if (iVar6 < 0x2e12685c) {
                iVar2 = 0x38a91317;
                if ((iVar6 != 0x252128c1) && (iVar2 = iVar6, iVar6 == 0x29ed482b)) {
                  iVar2 = 0x60f66ad3;
                }
              }
              else {
                iVar2 = -0x4fbf03dc;
                if (((iVar6 != 0x2e12685c) && (iVar2 = iVar6, iVar6 == 0x2ef88766)) &&
                   (uVar1 = (x.578 + -1) * x.578, bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0,
                   iVar2 = 0xf58d677, y.579 < 10 == bVar3 && (9 < y.579 || !bVar3))) {
                  iVar2 = -0x1ad44282;
                }
              }
            }
            else if (iVar6 < 0x3b872c59) {
              if (iVar6 == 0x376c6ad7) {
                iVar2 = 0x6a504c9c;
                if (local_99 == '\0') {
                  iVar2 = 0x72f8f9f4;
                }
              }
              else {
                iVar2 = -0x30ccddca;
                if ((iVar6 != 0x37f9a2c1) && (iVar2 = iVar6, iVar6 == 0x38a91317)) {
                  iVar2 = 0x6c97afca;
                }
              }
            }
            else if (iVar6 < 0x4ba5f8e1) {
              if (iVar6 == 0x3b872c59) {
                uVar1 = (x.578 + -1) * x.578;
                bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                iVar2 = -0x1828c2c6;
                if ((y.579 >= 10 || !bVar3) && y.579 < 10 == bVar3) {
                  iVar2 = -0x3feb1463;
                }
              }
              else if (iVar6 == 0x3ce41241) {
                uVar1 = (x.578 + -1) * x.578;
                bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                iVar2 = -0xbfe8746;
                if (y.579 < 10 == bVar3 && (9 < y.579 || !bVar3)) {
                  iVar2 = 0x524a9c3b;
                }
              }
            }
            else if (iVar6 == 0x4ba5f8e1) {
              local_c8 = (**(code **)(*param_1 + 0x548))(param_1,local_d0,0);
              iVar2 = -0x33aa9ed1;
              if (local_c8 != 0) {
                iVar2 = -0xcebe43c;
              }
            }
            else if (iVar6 == 0x51f36c43) {
              iVar2 = 0x6ffda744;
            }
          }
          if (iVar6 < 0x6bc3c63f) break;
          if (iVar6 < 0x6ffda744) {
            if (iVar6 == 0x6bc3c63f) {
              uVar1 = (x.578 + -1) * x.578;
              bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
              iVar2 = -0x3a8731cd;
              if (9 < y.579 == bVar3 && (9 < y.579 || bVar3)) {
                iVar2 = 0x244953a9;
              }
            }
            else if (iVar6 == 0x6c97afca) {
              uVar1 = (x.578 + -1) * x.578;
              bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
              iVar2 = 0x3ce41241;
              if ((y.579 >= 10 || !bVar3) && y.579 < 10 == bVar3) {
                iVar2 = 0x524a9c3b;
              }
            }
            else if (iVar6 == 0x6cb5669c) {
              iVar2 = -0x57655c6f;
            }
          }
          else if (iVar6 < 0x762377c0) {
            if (iVar6 == 0x6ffda744) {
              uVar1 = (x.578 + -1) * x.578;
              bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
              iVar2 = -0x3796b8ba;
              if ((y.579 >= 10 || !bVar3) && y.579 < 10 == bVar3) {
                iVar2 = 0x51f36c43;
              }
            }
            else if (iVar6 == 0x72f8f9f4) {
              local_98 = (**(code **)(*param_1 + 0x548))(param_1,local_a8,0);
              iVar2 = 0x6cb5669c;
              if (local_98 != 0) {
                iVar2 = -0x70b14076;
              }
            }
          }
          else {
            iVar2 = 0x25109070;
            if ((iVar6 != 0x762377c0) && (iVar2 = iVar6, iVar6 == 0x7df5ff39)) {
              uVar1 = (x.578 + -1) * x.578;
              bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
              iVar2 = 0xb4cb5e8;
              if (9 < y.579 == bVar3 && (9 < y.579 || bVar3)) {
                iVar2 = 0xefe6fa;
              }
            }
          }
        }
        if (iVar6 < 0x5d24df2a) break;
        if (iVar6 < 0x66185962) {
          if (iVar6 == 0x5d24df2a) {
            local_e8 = (**(code **)(*param_1 + 0x108))(param_1,local_f0,&DAT_0013f700,&DAT_0013f720)
            ;
            iVar2 = 0x762377c0;
            if (local_e8 != 0) {
              iVar2 = 0xc570878;
            }
          }
          else if (iVar6 == 0x60f66ad3) {
            bVar3 = ((x.578 + -1) * x.578 & 1U) == 0;
            iVar2 = -0x230daf6e;
            if ((y.579 >= 10 || !bVar3) && y.579 < 10 == bVar3) {
              iVar2 = -0x3ec9bddc;
            }
          }
        }
        else if (iVar6 == 0x66185962) {
          uVar1 = (x.578 + -1) * x.578;
          bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
          iVar2 = 0x3b872c59;
          if (y.579 < 10 == bVar3 && (9 < y.579 || !bVar3)) {
            iVar2 = -0x3feb1463;
          }
        }
        else if (iVar6 == 0x6a504c9c) {
          iVar2 = 0x29ed482b;
        }
      }
      if (0x56fed720 < iVar6) break;
      iVar2 = 0x3ce41241;
      if ((iVar6 != 0x524a9c3b) && (iVar2 = iVar6, iVar6 == 0x5581e668)) {
        iVar2 = 0x60f66ad3;
      }
    }
    iVar2 = 0x56fed721;
  } while ((iVar6 == 0x5b3141f8) || (iVar2 = iVar6, iVar6 != 0x56fed721));
  return 0;
}

