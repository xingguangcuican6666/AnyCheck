
undefined8
Java_luna_safe_luna_MainActivity_bootloaders(long *param_1,undefined8 param_2,undefined8 param_3)

{
  uint uVar1;
  int iVar2;
  bool bVar3;
  undefined8 uVar4;
  int iVar5;
  code *pcVar6;
  undefined1 auStack_4e0 [512];
  undefined1 auStack_2e0 [256];
  undefined1 auStack_1e0 [256];
  long lStack_e0;
  long lStack_d8;
  long lStack_d0;
  long lStack_c8;
  long lStack_c0;
  undefined1 *puStack_b8;
  undefined1 *puStack_b0;
  long lStack_a8;
  long lStack_a0;
  long lStack_98;
  undefined1 *puStack_90;
  undefined8 uStack_88;
  undefined1 *puStack_80;
  undefined1 *puStack_78;
  long lStack_70;
  
  lStack_e0 = (**(code **)(*param_1 + 0xf8))();
  iVar2 = -0x21cfa06f;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          while( true ) {
            while (iVar5 = iVar2, iVar2 = iVar5, 0x4ca4f7a < iVar5) {
              if (iVar5 < 0x3b5c3183) {
                if (iVar5 < 0x19dea377) {
                  if (iVar5 < 0x14096dbe) {
                    if (iVar5 == 0x4ca4f7b) {
                      uVar1 = (x.574 + -1) * x.574;
                      bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                      iVar2 = -0x4cb22bc8;
                      if ((y.575 >= 10 || !bVar3) && y.575 < 10 == bVar3) {
                        iVar2 = 0x1443d433;
                      }
                    }
                    else if (iVar5 == 0x58e4127) {
                      uVar4 = func_0x0013b6a0(0);
                      puStack_b8 = auStack_1e0;
                      puStack_b0 = puStack_b8;
                      func_0x0013b7b0(puStack_b8,0x100,0x13f7e0,lStack_c0,uVar4);
                      lStack_a8 = (**(code **)(*param_1 + 0x108))
                                            (param_1,lStack_e0,0x13f750,0x13f760);
                      iVar2 = 0x40734020;
                      if (lStack_a8 != 0) {
                        iVar2 = -0x78070149;
                      }
                    }
                    else if (iVar5 == 0x79f9482) {
                      uVar1 = (x.574 + -1) * x.574;
                      bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                      iVar2 = -0x79ff901f;
                      if ((y.575 >= 10 || !bVar3) && y.575 < 10 == bVar3) {
                        iVar2 = -0x4917cee4;
                      }
                    }
                  }
                  else if (iVar5 == 0x14096dbe) {
                    uVar1 = (x.574 + -1) * x.574;
                    bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                    iVar2 = 0x276390d9;
                    if (y.575 < 10 == bVar3 && (9 < y.575 || !bVar3)) {
                      iVar2 = 0x7c9fcc08;
                    }
                  }
                  else {
                    iVar2 = -0x4cb22bc8;
                    if ((iVar5 != 0x1443d433) && (iVar2 = iVar5, iVar5 == 0x185d2b94)) {
                      iVar2 = 0x4ecc7682;
                    }
                  }
                }
                else if (iVar5 < 0x23702c04) {
                  iVar2 = 0x79f9482;
                  if (iVar5 != 0x19dea377) {
                    if (iVar5 == 0x1b49fbe4) {
                      lStack_d8 = (**(code **)(*param_1 + 0x108))
                                            (param_1,lStack_e0,0x13f700,0x13f720);
                      iVar2 = 0x4ebc1891;
                      if (lStack_d8 != 0) {
                        iVar2 = 0x5d1a833c;
                      }
                    }
                    else {
                      iVar2 = iVar5;
                      if (iVar5 == 0x1cca629c) {
                        uVar1 = (x.574 + -1) * x.574 & 1;
                        iVar2 = 0x14096dbe;
                        if (y.575 < 10 == (uVar1 == 0) && (9 < y.575 | uVar1) == 1) {
                          iVar2 = 0x7c9fcc08;
                        }
                      }
                    }
                  }
                }
                else if (iVar5 < 0x276390d9) {
                  iVar2 = 0x4ca4f7b;
                  if ((iVar5 != 0x23702c04) && (iVar2 = iVar5, iVar5 == 0x26ef31e1)) {
                    iVar2 = -0x439e45fc;
                  }
                }
                else {
                  iVar2 = -0x25b1fb3a;
                  if ((iVar5 != 0x276390d9) && (iVar2 = iVar5, iVar5 == 0x27f43c6b)) {
                    iVar2 = -0x5b0d5fb3;
                  }
                }
              }
              else if (iVar5 < 0x5a464ab0) {
                if (iVar5 < 0x4ebc1891) {
                  if (iVar5 == 0x3b5c3183) {
                    uVar1 = (x.574 + -1) * x.574;
                    bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
                    iVar2 = -0x5547675;
                    if (9 < y.575 == bVar3 && (9 < y.575 || bVar3)) {
                      iVar2 = -0x4d21ae48;
                    }
                  }
                  else if (iVar5 == 0x40734020) {
                    uVar1 = (x.574 + -1) * x.574;
                    bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                    iVar2 = -0x1849707f;
                    if ((y.575 >= 10 || !bVar3) && y.575 < 10 == bVar3) {
                      iVar2 = 0x56840d3a;
                    }
                  }
                  else if (iVar5 == 0x486a721f) {
                    iVar2 = -0x2f5af639;
                  }
                }
                else if (iVar5 < 0x54d3c571) {
                  iVar2 = 0x4ca4f7b;
                  if ((iVar5 != 0x4ebc1891) && (iVar2 = iVar5, iVar5 == 0x4ecc7682)) {
                    uVar1 = (x.574 + -1) * x.574 & 1;
                    iVar2 = 0x27f43c6b;
                    if (y.575 < 10 == (uVar1 == 0) && (9 < y.575 | uVar1) == 1) {
                      iVar2 = 0x185d2b94;
                    }
                  }
                }
                else if (iVar5 == 0x54d3c571) {
                  lStack_c0 = (**(code **)(*param_1 + 0x548))(param_1,lStack_c8,0);
                  iVar2 = 0x7a9e33ad;
                  if (lStack_c0 != 0) {
                    iVar2 = 0x58e4127;
                  }
                }
                else if (iVar5 == 0x56840d3a) {
                  iVar2 = -0x1849707f;
                }
              }
              else if (iVar5 < 0x6d969199) {
                if (iVar5 == 0x5a464ab0) {
                  puStack_90 = auStack_2e0;
                  func_0x0013b7b0(puStack_90,auStack_2e0,0x100,0x13f7f8,lStack_98);
                  uStack_88 = (**(code **)(*param_1 + 0x548))(param_1,param_3,0);
                  puStack_80 = auStack_4e0;
                  puStack_78 = puStack_80;
                  func_0x0013b7b0(puStack_80,puStack_80,0x200,0x13f798,uStack_88,auStack_2e0);
                  lStack_70 = (**(code **)(*param_1 + 0x108))(param_1,lStack_e0,0x13f7a0,0x13f7c0);
                  iVar2 = 0x1cca629c;
                  if (lStack_70 != 0) {
                    iVar2 = -0x72ff78bf;
                  }
                }
                else if (iVar5 == 0x5d1a833c) {
                  lStack_d0 = (**(code **)(*param_1 + 0x110))(param_1,param_2,lStack_d8);
                  iVar2 = 0x3b5c3183;
                  if (lStack_d0 != 0) {
                    iVar2 = 0x5d90fab9;
                  }
                }
                else if (iVar5 == 0x5d90fab9) {
                  lStack_c8 = (**(code **)(*param_1 + 0x568))(param_1,lStack_d0,0);
                  iVar2 = -0x27e56cae;
                  if (lStack_c8 != 0) {
                    iVar2 = 0x54d3c571;
                  }
                }
              }
              else if (iVar5 < 0x7a9e33ad) {
                iVar2 = -0x5f26af0b;
                if ((iVar5 != 0x6d969199) && (iVar2 = iVar5, iVar5 == 0x6f41ab5f)) {
                  iVar2 = 0x19dea377;
                }
              }
              else {
                iVar2 = 0x19dea377;
                if ((iVar5 != 0x7a9e33ad) && (iVar2 = iVar5, iVar5 == 0x7c9fcc08)) {
                  iVar2 = 0x14096dbe;
                }
              }
            }
            if (iVar5 < -0x3c2a3eec) break;
            if (iVar5 < -0x25b1fb3a) {
              if (iVar5 < -0x2f5af639) {
                iVar2 = -0x4b596823;
                if (((iVar5 != -0x3c2a3eec) && (iVar2 = 0x23702c04, iVar5 != -0x3209dba4)) &&
                   (iVar2 = iVar5, iVar5 == -0x31b892ab)) {
                  iVar2 = 0x79f9482;
                }
              }
              else if (iVar5 < -0x2ccc06c3) {
                iVar2 = -0x2ccc06c3;
                if ((iVar5 != -0x2f5af639) && (iVar2 = iVar5, iVar5 == -0x2e010570)) {
                  uVar1 = (x.574 + -1) * x.574 & 1;
                  iVar2 = 0x4ecc7682;
                  if (9 < y.575 == uVar1 && (9 < y.575 | uVar1) == 1) {
                    iVar2 = 0x185d2b94;
                  }
                }
              }
              else {
                iVar2 = -0x439e45fc;
                if ((iVar5 != -0x2ccc06c3) && (iVar2 = iVar5, iVar5 == -0x27e56cae)) {
                  uVar1 = (x.574 + -1) * x.574 & 1;
                  iVar2 = -0x21a882be;
                  if (y.575 < 10 == (uVar1 == 0) && (9 < y.575 | uVar1) == 1) {
                    iVar2 = -0x4169659c;
                  }
                }
              }
            }
            else if (iVar5 < -0x1a0f01b7) {
              if (iVar5 == -0x25b1fb3a) {
                iVar2 = -0x2f5af639;
              }
              else if (iVar5 == -0x21cfa06f) {
                iVar2 = -0x2e010570;
                if (lStack_e0 != 0) {
                  iVar2 = 0x1b49fbe4;
                }
              }
              else if (iVar5 == -0x21a882be) {
                uVar1 = (x.574 + -1) * x.574;
                bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                iVar2 = -0x31b892ab;
                if ((y.575 >= 10 || !bVar3) && y.575 < 10 == bVar3) {
                  iVar2 = -0x4169659c;
                }
              }
            }
            else if (iVar5 < -0x89e7106) {
              iVar2 = -0x5b0d5fb3;
              if ((iVar5 != -0x1a0f01b7) && (iVar2 = iVar5, iVar5 == -0x1849707f)) {
                uVar1 = (x.574 + -1) * x.574 & 1;
                iVar2 = 0x26ef31e1;
                if (9 < y.575 == uVar1 && (9 < y.575 | uVar1) == 1) {
                  iVar2 = 0x56840d3a;
                }
              }
            }
            else {
              iVar2 = -0x2ccc06c3;
              if ((iVar5 != -0x89e7106) && (iVar2 = iVar5, iVar5 == -0x5547675)) {
                uVar1 = (x.574 + -1) * x.574 & 1;
                iVar2 = -0x3209dba4;
                if (y.575 < 10 == (uVar1 == 0) && (9 < y.575 | uVar1) == 1) {
                  iVar2 = -0x4d21ae48;
                }
              }
            }
          }
          if (iVar5 < -0x4d21ae48) break;
          if (iVar5 < -0x4917cee4) {
            iVar2 = -0x5547675;
            if (iVar5 != -0x4d21ae48) {
              if (iVar5 == -0x4cb22bc8) {
                uVar1 = (x.574 + -1) * x.574 & 1;
                iVar2 = -0x1a0f01b7;
                if (y.575 < 10 == (uVar1 == 0) && (9 < y.575 | uVar1) == 1) {
                  iVar2 = 0x1443d433;
                }
              }
              else {
                iVar2 = iVar5;
                if (iVar5 == -0x4b596823) {
                  uVar1 = (x.574 + -1) * x.574 & 1;
                  iVar2 = 0x486a721f;
                  if (y.575 < 10 == (uVar1 == 0) && (9 < y.575 | uVar1) == 1) {
                    iVar2 = -0x3c2a3eec;
                  }
                }
              }
            }
          }
          else if (iVar5 < -0x416d5744) {
            iVar2 = -0x79ff901f;
            if ((iVar5 != -0x4917cee4) && (iVar2 = iVar5, iVar5 == -0x439e45fc)) {
              uVar1 = (x.574 + -1) * x.574;
              bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
              iVar2 = -0x5f26af0b;
              if ((y.575 >= 10 || !bVar3) && y.575 < 10 == bVar3) {
                iVar2 = 0x6d969199;
              }
            }
          }
          else if (iVar5 == -0x416d5744) {
            uVar1 = (x.574 + -1) * x.574 & 1;
            iVar2 = -0x4b596823;
            if (9 < y.575 == uVar1 && (9 < y.575 | uVar1) == 1) {
              iVar2 = -0x3c2a3eec;
            }
          }
          else if (iVar5 == -0x4169659c) {
            iVar2 = -0x21a882be;
          }
        }
        if (-0x6c5b9f63 < iVar5) break;
        if (iVar5 == -0x79ff901f) {
          uVar1 = (x.574 + -1) * x.574 & 1;
          iVar2 = -0x513716a9;
          if (9 < y.575 == uVar1 && (9 < y.575 | uVar1) == 1) {
            iVar2 = -0x4917cee4;
          }
        }
        else if (iVar5 == -0x78070149) {
          uVar4 = (**(code **)(*param_1 + 0x538))(param_1,puStack_b0);
          lStack_a0 = (**(code **)(*param_1 + 0x110))(param_1,param_2,lStack_a8,uVar4);
          iVar2 = -0x89e7106;
          if (lStack_a0 != 0) {
            iVar2 = -0x6c5b9f62;
          }
        }
        else if (iVar5 == -0x72ff78bf) {
          pcVar6 = *(code **)(*param_1 + 0x1e8);
          uVar4 = (**(code **)(*param_1 + 0x538))(param_1,puStack_78);
          (*pcVar6)(param_1,param_2,lStack_70,uVar4);
          (**(code **)(*param_1 + 0x550))(param_1,lStack_c8,lStack_c0);
          (**(code **)(*param_1 + 0x550))(param_1,lStack_a0,lStack_98);
          (**(code **)(*param_1 + 0x550))(param_1,param_3,uStack_88);
          iVar2 = -0x25b1fb3a;
        }
      }
      if (-0x5b0d5fb4 < iVar5) break;
      if (iVar5 == -0x6c5b9f62) {
        lStack_98 = (**(code **)(*param_1 + 0x548))(param_1,lStack_a0,0);
        iVar2 = -0x416d5744;
        if (lStack_98 != 0) {
          iVar2 = 0x5a464ab0;
        }
      }
      else if (iVar5 == -0x5f26af0b) {
        uVar1 = (x.574 + -1) * x.574;
        bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
        iVar2 = 0x6f41ab5f;
        if ((y.575 >= 10 || !bVar3) && y.575 < 10 == bVar3) {
          iVar2 = 0x6d969199;
        }
      }
    }
    iVar2 = 0x23702c04;
  } while ((iVar5 == -0x513716a9) || (iVar2 = iVar5, iVar5 != -0x5b0d5fb3));
  return 0;
}

