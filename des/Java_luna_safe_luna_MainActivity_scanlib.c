
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

dirent * Java_luna_safe_luna_MainActivity_scanlib(dirent *param_1,undefined8 param_2)

{
  int iVar1;
  dirent *pdVar2;
  bool bVar3;
  uint uVar4;
  undefined8 uVar5;
  dirent *pdVar6;
  int iVar7;
  int local_1cc;
  dirent *local_1c8;
  dirent *local_1c0;
  int local_1b4;
  int local_1b0;
  int local_1ac;
  int local_1a8;
  int local_1a4;
  int local_1a0;
  int local_19c;
  int local_198;
  int local_194;
  dirent *local_188;
  dirent *local_180;
  dirent *local_178;
  dirent *local_170;
  undefined8 local_168;
  dirent *local_160;
  dirent *local_158;
  char local_149;
  undefined8 local_148;
  long local_140;
  dirent *local_138;
  char local_12d;
  int local_12c;
  dirent *local_128;
  char local_119;
  undefined8 local_118;
  long local_110;
  dirent *local_108;
  long local_100;
  dirent *local_f8;
  byte local_ea;
  byte local_e9;
  dirent *local_e8;
  byte local_d9;
  dirent *local_d8;
  dirent *local_d0;
  char *local_c8;
  dirent *local_c0;
  char local_b1;
  undefined8 local_b0;
  undefined8 local_a8;
  int local_9c;
  char local_95;
  int local_94;
  char local_8d;
  int local_8c;
  dirent *local_88;
  dirent *local_80;
  int local_78;
  int local_74;
  int local_70;
  int local_6c;
  
  pdVar2 = DAT_00143b40;
  uRam0000000000143a41 = 0;
  _DAT_00143a39 = 0;
  uRam0000000000143a51 = 0;
  _DAT_00143a49 = 0;
  uRam0000000000143a61 = 0;
  _DAT_00143a59 = 0;
  uRam0000000000143a71 = 0;
  _DAT_00143a69 = 0;
  uRam0000000000143a81 = 0;
  _DAT_00143a79 = 0;
  uRam0000000000143a91 = 0;
  _DAT_00143a89 = 0;
  uRam0000000000143aa1 = 0;
  _DAT_00143a99 = 0;
  uRam0000000000143ab1 = 0;
  _DAT_00143aa9 = 0;
  uRam0000000000143ac1 = 0;
  _DAT_00143ab9 = 0;
  uRam0000000000143ad1 = 0;
  _DAT_00143ac9 = 0;
  uRam0000000000143ae1 = 0;
  _DAT_00143ad9 = 0;
  uRam0000000000143af1 = 0;
  _DAT_00143ae9 = 0;
  uRam0000000000143b01 = 0;
  _DAT_00143af9 = 0;
  uRam0000000000143b11 = 0;
  _DAT_00143b09 = 0;
  uRam0000000000143b21 = 0;
  _DAT_00143b19 = 0;
  uRam0000000000143b31 = 0;
  _DAT_00143b29 = 0;
  DAT_00143938 = 0;
  uRam0000000000143941 = 0;
  _DAT_00143939 = 0;
  uRam0000000000143951 = 0;
  _DAT_00143949 = 0;
  uRam0000000000143961 = 0;
  _DAT_00143959 = 0;
  uRam0000000000143971 = 0;
  _DAT_00143969 = 0;
  uRam0000000000143981 = 0;
  _DAT_00143979 = 0;
  uRam0000000000143991 = 0;
  _DAT_00143989 = 0;
  uRam00000000001439a1 = 0;
  _DAT_00143999 = 0;
  uRam00000000001439b1 = 0;
  _DAT_001439a9 = 0;
  uRam00000000001439c1 = 0;
  _DAT_001439b9 = 0;
  uRam00000000001439d1 = 0;
  _DAT_001439c9 = 0;
  uRam00000000001439e1 = 0;
  _DAT_001439d9 = 0;
  uRam00000000001439f1 = 0;
  _DAT_001439e9 = 0;
  uRam0000000000143a01 = 0;
  _DAT_001439f9 = 0;
  uRam0000000000143a11 = 0;
  _DAT_00143a09 = 0;
  uRam0000000000143a21 = 0;
  _DAT_00143a19 = 0;
  uRam0000000000143a31 = 0;
  _DAT_00143a29 = 0;
  pdVar6 = param_1;
  iVar1 = -0x756ff036;
LAB_00115d30:
  do {
    while( true ) {
      while (iVar7 = iVar1, iVar1 = iVar7, -0xa0ccf7 < iVar7) {
        if (iVar7 < 0x4034ef6b) {
          if (iVar7 < 0x212a2ec6) {
            if (iVar7 < 0xeaa4fe0) {
              if (iVar7 < 0x7313b23) {
                if (iVar7 < 0x577ff43) {
                  if (iVar7 == -0xa0ccf6) {
                    local_b0 = (**(code **)(param_1->d_ino + 0x538))(param_1,local_c8);
                    local_a8 = (**(code **)(param_1->d_ino + 0x538))(param_1,local_80);
                    (**(code **)(param_1->d_ino + 0x128))
                              (param_1,param_2,local_180,local_b0,local_a8);
                    pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x720))(param_1);
                    iVar1 = 0x7179d075;
                    if (((ulong)pdVar6 & 0xff) != 0) {
                      iVar1 = -0x47aaaabc;
                    }
                  }
                  else if (iVar7 == 0x186640e) {
                    pdVar6 = (dirent *)__android_log_print(6,&DAT_0013f18c,&DAT_0013fc70);
                    iVar1 = 0x43e7f5f3;
                  }
                }
                else {
                  iVar1 = -0x5084168b;
                  if ((iVar7 != 0x577ff43) && (iVar1 = iVar7, iVar7 == 0x6ab5622)) {
                    iVar1 = -0xa0ccf6;
                    if (local_b1 == '\0') {
                      iVar1 = 0x18cb01a2;
                    }
                  }
                }
              }
              else if (iVar7 < 0xa1b85b8) {
                if (iVar7 == 0x7313b23) {
                  bVar3 = ((x.588 + -1) * x.588 & 1U) == 0;
                  iVar1 = 0x16c9a1f1;
                  if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                    iVar1 = 0x72028e30;
                  }
                }
                else if (iVar7 == 0x78f495e) {
                  local_1a8 = local_9c;
                  iVar1 = -0x7b86ba96;
                }
              }
              else if (iVar7 == 0xa1b85b8) {
                pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0xb8))(param_1,local_128);
                local_19c = 4;
                iVar1 = 0x2d57b715;
              }
              else if (iVar7 == 0xd0c6a2e) {
                bVar3 = ((x.588 + -1) * x.588 & 1U) == 0;
                iVar1 = -0x3376d704;
                if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                  iVar1 = -0x5a7ddb0d;
                }
              }
              else if (iVar7 == 0xd488271) {
                local_1a0 = 0;
                iVar1 = -0x47f8f0d;
              }
            }
            else if (iVar7 < 0x16c9a1f1) {
              if (iVar7 < 0x11fdbab6) {
                if (iVar7 == 0xeaa4fe0) {
                  pdVar6 = (dirent *)__android_log_print(6,&DAT_0013f18c,&DAT_0013fce0);
                  iVar1 = 0x6dfbb282;
                }
                else if (iVar7 == 0xfecb8cf) {
                  iVar1 = 0x573ea845;
                  if (local_95 == '\0') {
                    iVar1 = 0xd488271;
                  }
                }
              }
              else if (iVar7 == 0x11fdbab6) {
                local_9c = local_78 + 1;
                uVar4 = (x.588 + -1) * x.588;
                bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
                iVar1 = 0x78f495e;
                if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                  iVar1 = 0x1c8a5567;
                }
              }
              else {
                iVar1 = 0x4249606f;
                if ((iVar7 != 0x15610b8e) && (iVar1 = iVar7, iVar7 == 0x15689fa3)) {
                  local_1b4 = 0;
                  iVar1 = 0x662c2c7a;
                }
              }
            }
            else if (iVar7 < 0x1c8a5567) {
              if (iVar7 == 0x16c9a1f1) {
                bVar3 = ((x.588 + -1) * x.588 & 1U) == 0;
                iVar1 = -0x53969f19;
                if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                  iVar1 = 0x72028e30;
                }
              }
              else if (iVar7 == 0x18cb01a2) {
                bVar3 = ((x.588 + -1) * x.588 & 1U) == 0;
                iVar1 = 0x212a2ec6;
                if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                  iVar1 = -0x4e062696;
                }
              }
            }
            else if (iVar7 == 0x1c8a5567) {
              iVar1 = 0x11fdbab6;
            }
            else if (iVar7 == 0x1f248965) {
              uVar5 = (**(code **)(param_1->d_ino + 0xf8))(param_1,local_158);
              (**(code **)(param_1->d_ino + 0x108))(param_1,uVar5,&DAT_0013fd3c,&DAT_0013fd44);
              pdVar6 = (dirent *)
                       (**(code **)(param_1->d_ino + 0x108))
                                 (param_1,uVar5,&DAT_0013fd48,&DAT_0013fd50);
              iVar1 = 0x2c7574a3;
            }
            else if (iVar7 == 0x20a671cb) {
              uVar4 = (x.588 + -1) * x.588;
              bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
              iVar1 = -0x5eaddabc;
              if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                iVar1 = -0x79f547b5;
              }
            }
          }
          else if (iVar7 < 0x2de422c2) {
            if (iVar7 < 0x286988e5) {
              if (iVar7 < 0x26ffdab8) {
                if (iVar7 == 0x212a2ec6) {
                  uVar4 = closedir((DIR *)local_d8);
                  pdVar6 = (dirent *)(ulong)uVar4;
                  bVar3 = ((x.588 + -1) * x.588 & 1U) == 0;
                  iVar1 = 0x73d639c6;
                  if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                    iVar1 = -0x4e062696;
                  }
                }
                else if (iVar7 == 0x2517af24) {
                  iVar1 = -0x4eab77a6;
                }
              }
              else {
                iVar1 = 0x4ec7ebd5;
                if ((iVar7 != 0x26ffdab8) && (iVar1 = iVar7, iVar7 == 0x271db537)) {
                  bVar3 = ((x.588 + -1) * x.588 & 1U) == 0;
                  iVar1 = -0x68bbf383;
                  if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                    iVar1 = 0x286988e5;
                  }
                }
              }
            }
            else if (iVar7 < 0x28f4f1b4) {
              if (iVar7 == 0x286988e5) {
                pdVar6 = (dirent *)__android_log_print(6,&DAT_0013f18c,&DAT_0013fd10);
                iVar1 = -0x68bbf383;
              }
              else if (iVar7 == 0x2891f687) {
                local_8c = local_1b0;
                iVar1 = 0x687698de;
                if (local_12c <= local_1b0) {
                  iVar1 = 0x3c04df8c;
                }
              }
            }
            else if (iVar7 == 0x28f4f1b4) {
              uVar4 = (x.588 + -1) * x.588;
              bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) != 0;
              iVar1 = -0xa039aa8;
              if (9 < y.589 == bVar3 && (9 < y.589 || bVar3)) {
                iVar1 = 0x40fd7684;
              }
            }
            else if (iVar7 == 0x2c7574a3) {
              local_148 = (**(code **)(param_1->d_ino + 0xf8))(param_1,local_158);
              local_140 = (**(code **)(param_1->d_ino + 0x108))
                                    (param_1,local_148,&DAT_0013fd3c,&DAT_0013fd44);
              pdVar6 = (dirent *)
                       (**(code **)(param_1->d_ino + 0x108))
                                 (param_1,local_148,&DAT_0013fd48,&DAT_0013fd50);
              uVar4 = (x.588 + -1) * x.588;
              local_12d = local_140 == 0 && pdVar6 == (dirent *)0x0 ||
                          (local_140 == 0) != (pdVar6 == (dirent *)0x0);
              bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
              iVar1 = -0x5f6677e9;
              local_138 = pdVar6;
              if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                iVar1 = 0x1f248965;
              }
            }
            else if (iVar7 == 0x2d57b715) {
              local_198 = local_19c;
              iVar1 = 0x6386fb7c;
            }
          }
          else if (iVar7 < 0x3943a493) {
            if (iVar7 < 0x3246a09e) {
              if (iVar7 == 0x2de422c2) {
                local_1b0 = local_94;
                iVar1 = 0x2891f687;
              }
              else if (iVar7 == 0x31aa3236) {
                local_194 = local_70;
                iVar1 = 0x5ad5cafe;
              }
            }
            else if (iVar7 == 0x3246a09e) {
              bVar3 = ((x.588 + -1) * x.588 & 1U) == 0;
              iVar1 = -0x7a2c5013;
              if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                iVar1 = -0x42e68bad;
              }
            }
            else if (iVar7 == 0x335dd063) {
              pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0xa8))(param_1,param_2);
              uVar4 = (x.588 + -1) * x.588;
              bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
              iVar1 = -0x3210d4e;
              DAT_00143b40 = pdVar6;
              if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                iVar1 = -0x22e430b7;
              }
            }
            else if (iVar7 == 0x3648217b) {
              pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x110))(param_1,param_2,local_178);
              iVar1 = 0x20a671cb;
              local_170 = pdVar6;
              if (pdVar6 != (dirent *)0x0) {
                iVar1 = -0xb776e14;
              }
            }
          }
          else if (iVar7 < 0x3c04df8c) {
            if (iVar7 == 0x3943a493) {
              local_100 = (**(code **)(param_1->d_ino + 0x2f8))(param_1,local_128,local_110);
              pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x2f8))(param_1,local_128,local_108);
              local_1c8 = (dirent *)0x0;
              local_ea = local_100 != 0;
              iVar1 = -0x4083cec4;
              local_f8 = pdVar6;
              if (!(bool)local_ea) {
                iVar1 = 0x490643cd;
              }
            }
            else if (iVar7 == 0x3af318b4) {
              iVar1 = -0x38c32dca;
            }
          }
          else if (iVar7 == 0x3c04df8c) {
            local_194 = 2;
            iVar1 = 0x5ad5cafe;
          }
          else if (iVar7 == 0x3d071ebc) {
            local_1a4 = local_1ac;
            iVar1 = -0x5ddf82f;
            if (local_1ac != 0) {
              iVar1 = 0x6346a926;
            }
          }
          else if (iVar7 == 0x3ff13eb6) {
            uVar4 = strcmp(local_c8,(&PTR_DAT_0013d128)[local_78]);
            pdVar6 = (dirent *)(ulong)uVar4;
            iVar1 = 0x68c02b8d;
            if (uVar4 != 0) {
              iVar1 = -0x40023964;
            }
          }
        }
        else if (iVar7 < 0x62c5c60d) {
          if (iVar7 < 0x4a851dfd) {
            if (iVar7 < 0x43e7f5f3) {
              if (iVar7 < 0x40fd7684) {
                iVar1 = -0x29eedbb1;
                if ((iVar7 != 0x4034ef6b) && (iVar1 = iVar7, iVar7 == 0x40bf23ae)) {
                  iVar1 = 0x6b2d147c;
                }
              }
              else if (iVar7 == 0x40fd7684) {
                pdVar6 = (dirent *)
                         (**(code **)(param_1->d_ino + 0x110))(param_1,local_170,local_160,0);
                iVar1 = -0xa039aa8;
              }
              else if (iVar7 == 0x4249606f) {
                iVar1 = 0x7313b23;
              }
            }
            else if (iVar7 < 0x45e7ef1c) {
              if (iVar7 == 0x43e7f5f3) {
                uVar4 = (x.588 + -1) * x.588;
                bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
                iVar1 = -0x5084168b;
                if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                  iVar1 = 0x577ff43;
                }
              }
              else if (iVar7 == 0x44a28ffa) {
                pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x550))(param_1,local_100,local_88)
                ;
                iVar1 = -0x4af647d;
              }
            }
            else if (iVar7 == 0x45e7ef1c) {
              local_19c = local_74;
              iVar1 = 0x2d57b715;
            }
            else if (iVar7 == 0x470ec47f) {
              uVar4 = (x.588 + -1) * x.588;
              bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
              iVar1 = -0x4eab77a6;
              if (y.589 < 10 == bVar3 && (9 < y.589 || !bVar3)) {
                iVar1 = 0x2517af24;
              }
            }
            else if (iVar7 == 0x490643cd) {
              local_88 = local_1c8;
              local_e9 = local_f8 != (dirent *)0x0;
              iVar1 = -0x24301b23;
              if (!(bool)local_e9) {
                iVar1 = 0x6dd7e830;
              }
              local_1c0 = (dirent *)&DAT_0013fdb8;
            }
          }
          else if (iVar7 < 0x541c1837) {
            if (iVar7 < 0x4ec7ebd5) {
              if (iVar7 == 0x4a851dfd) {
                uVar4 = (x.588 + -1) * x.588;
                bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) != 0;
                iVar1 = 0x62c5c60d;
                if (9 < y.589 == bVar3 && (9 < y.589 || bVar3)) {
                  iVar1 = 0x4a9ae3f9;
                }
              }
              else if (iVar7 == 0x4a9ae3f9) {
                uVar4 = closedir((DIR *)local_d8);
                pdVar6 = (dirent *)(ulong)uVar4;
                iVar1 = 0x62c5c60d;
              }
            }
            else if (iVar7 == 0x4ec7ebd5) {
              pdVar6 = readdir((DIR *)local_d8);
              iVar1 = 0x4a851dfd;
              local_d0 = pdVar6;
              if (pdVar6 != (dirent *)0x0) {
                iVar1 = -0x6ec57d00;
              }
            }
            else if (iVar7 == 0x502e0749) {
              pdVar6 = (dirent *)
                       (**(code **)(param_1->d_ino + 0x110))(param_1,local_158,local_138,local_8c);
              iVar1 = -0x1779f423;
            }
            else if (iVar7 == 0x5394626a) {
              (**(code **)(param_1->d_ino + 0xb8))(param_1,local_128);
              (**(code **)(param_1->d_ino + 0xb8))(param_1,local_118);
              (**(code **)(param_1->d_ino + 0xb8))(param_1,local_148);
              (**(code **)(param_1->d_ino + 0xb8))(param_1,local_158);
              (**(code **)(param_1->d_ino + 0xb8))(param_1,local_168);
              (**(code **)(param_1->d_ino + 0xb8))(param_1,local_170);
              pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0xb8))(param_1,local_188);
              local_1cc = 1;
              iVar1 = -0x4662436e;
            }
          }
          else if (iVar7 < 0x5ad5cafe) {
            iVar1 = 0x43e7f5f3;
            if ((iVar7 != 0x541c1837) && (iVar1 = iVar7, iVar7 == 0x573ea845)) {
              pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x88))(param_1);
              iVar1 = 0xd488271;
            }
          }
          else if (iVar7 == 0x5ad5cafe) {
            uVar4 = (x.588 + -1) * x.588;
            bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
            iVar1 = -0x25e91028;
            if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
              iVar1 = -0x426f4854;
            }
            local_6c = local_194;
          }
          else if (iVar7 == 0x5b102eb5) {
            (**(code **)(param_1->d_ino + 0xb8))(param_1,local_128);
            (**(code **)(param_1->d_ino + 0xb8))(param_1,local_118);
            pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x720))(param_1);
            iVar1 = -0x7cc8f830;
          }
          else if (iVar7 == 0x5c69feb4) {
            uVar4 = (x.588 + -1) * x.588;
            bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
            iVar1 = 0x6b2d147c;
            if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
              iVar1 = 0x40bf23ae;
            }
          }
        }
        else if (iVar7 < 0x6dd7e830) {
          if (iVar7 < 0x687698de) {
            if (iVar7 < 0x6386fb7c) {
              if (iVar7 == 0x62c5c60d) {
                uVar4 = closedir((DIR *)local_d8);
                pdVar6 = (dirent *)(ulong)uVar4;
                uVar4 = (x.588 + -1) * x.588;
                bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
                iVar1 = -0x5c90abf2;
                if (y.589 < 10 == bVar3 && (9 < y.589 || !bVar3)) {
                  iVar1 = 0x4a9ae3f9;
                }
              }
              else if (iVar7 == 0x6346a926) {
                local_1a0 = local_1a4;
                iVar1 = 0x7bf5cb9d;
                if (local_1a4 != 0) {
                  iVar1 = -0x47f8f0d;
                }
              }
            }
            else if (iVar7 == 0x6386fb7c) {
              uVar4 = (x.588 + -1) * x.588;
              bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
              iVar1 = -0x29eedbb1;
              if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                iVar1 = 0x4034ef6b;
              }
              local_70 = local_198;
            }
            else if (iVar7 == 0x662c2c7a) {
              local_1ac = local_1b4;
              iVar1 = -0xd995a11;
              if (local_1b4 != 0) {
                iVar1 = 0x3d071ebc;
              }
            }
            else if (iVar7 == 0x67c5d9d2) {
              local_1c0 = local_e8;
              iVar1 = 0x6dd7e830;
            }
          }
          else if (iVar7 < 0x6a6c4528) {
            if (iVar7 == 0x687698de) {
              uVar4 = (x.588 + -1) * x.588 & 1;
              iVar1 = -0x1779f423;
              if (y.589 < 10 == (uVar4 == 0) && (9 < y.589 | uVar4) == 1) {
                iVar1 = 0x502e0749;
              }
            }
            else if (iVar7 == 0x68c02b8d) {
              uVar4 = (x.588 + -1) * x.588;
              bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) != 0;
              iVar1 = -0x51a85956;
              if (9 < y.589 == bVar3 && (9 < y.589 || bVar3)) {
                iVar1 = 0x758ef6e7;
              }
            }
          }
          else if (iVar7 == 0x6a6c4528) {
            pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x548))(param_1,local_f8,0);
            iVar1 = -0x7145c3e0;
          }
          else if (iVar7 == 0x6b2d147c) {
            bVar3 = ((x.588 + -1) * x.588 & 1U) == 0;
            iVar1 = -0x1689e66c;
            if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
              iVar1 = 0x40bf23ae;
            }
          }
          else if (iVar7 == 0x6cb54976) {
            (**(code **)(param_1->d_ino + 0xb8))(param_1,local_b0);
            pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0xb8))(param_1,local_a8);
            uVar4 = (x.588 + -1) * x.588 & 1;
            iVar1 = -0x4208b2a3;
            if (9 < y.589 == uVar4 && (9 < y.589 | uVar4) == 1) {
              iVar1 = -0x646ce11b;
            }
          }
        }
        else if (iVar7 < 0x73d639c6) {
          if (iVar7 < 0x6e929da6) {
            if (iVar7 == 0x6dd7e830) {
              local_80 = local_1c0;
              local_d9 = local_88 != (dirent *)0x0;
              iVar1 = -0x54e25375;
              if (!(bool)local_d9) {
                iVar1 = 0x7bf5cb9d;
              }
            }
            else if (iVar7 == 0x6dfbb282) {
              pdVar6 = (dirent *)__android_log_print(6,&DAT_0013f18c,&DAT_0013fce0);
              uVar4 = (x.588 + -1) * x.588;
              bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) != 0;
              iVar1 = -0x4131e16f;
              if (9 < y.589 == bVar3 && (9 < y.589 || bVar3)) {
                iVar1 = 0xeaa4fe0;
              }
            }
          }
          else if (iVar7 == 0x6e929da6) {
            pdVar6 = (dirent *)__android_log_print(6,&DAT_0013f18c,&DAT_0013fbf0);
            iVar1 = -0x3bf7ba7;
          }
          else if (iVar7 == 0x7179d075) {
            uVar4 = (x.588 + -1) * x.588 & 1;
            iVar1 = 0x6cb54976;
            if (y.589 < 10 == (uVar4 == 0) && (9 < y.589 | uVar4) == 1) {
              iVar1 = -0x646ce11b;
            }
          }
          else if (iVar7 == 0x72028e30) {
            iVar1 = 0x16c9a1f1;
          }
        }
        else if (iVar7 < 0x77d814ba) {
          if (iVar7 == 0x73d639c6) {
            iVar1 = 0x44a28ffa;
            if (local_ea == 0) {
              iVar1 = -0x4af647d;
            }
          }
          else if (iVar7 == 0x758ef6e7) {
            __android_log_print(4,&DAT_0013f18c,&DAT_0013fdd0,local_c8,local_80);
            DAT_00143938 = 1;
            strncpy(&DAT_00143939,local_c8,0xff);
            pdVar6 = (dirent *)strncpy(&DAT_00143a39,(char *)local_80,0xff);
            iVar1 = -0x51a85956;
          }
        }
        else if (iVar7 == 0x77d814ba) {
          local_118 = (**(code **)(param_1->d_ino + 0xf8))(param_1,local_128);
          local_110 = (**(code **)(param_1->d_ino + 0x2f0))
                                (param_1,local_118,&DAT_0013fd90,&DAT_0013f9e0);
          pdVar6 = (dirent *)
                   (**(code **)(param_1->d_ino + 0x2f0))
                             (param_1,local_118,&DAT_0013fda8,&DAT_0013f9e0);
          iVar1 = 0xa1b85b8;
          local_108 = pdVar6;
          if ((local_110 == 0) == (pdVar6 == (dirent *)0x0) &&
              (local_110 != 0 || pdVar6 != (dirent *)0x0)) {
            iVar1 = 0x3943a493;
          }
        }
        else if (iVar7 == 0x7bf5cb9d) {
          iVar1 = -0xb298464;
          if ((local_ea & (local_d9 ^ local_ea ^ 0xff) & 1) == 0) {
            iVar1 = -0x57a98f09;
          }
        }
        else if (iVar7 == 0x7dc58bf7) {
          iVar1 = 0x4249606f;
        }
      }
      if (-0x4083cec5 < iVar7) break;
      if (iVar7 < -0x5b73fe66) {
        if (iVar7 < -0x7145c3e0) {
          if (iVar7 < -0x79f547b5) {
            if (iVar7 < -0x7b86ba96) {
              if (iVar7 == -0x7d706e86) {
                pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x550))(param_1,local_f8,local_80);
                iVar1 = -0x283e99a7;
              }
              else if (iVar7 == -0x7cc8f830) {
                (**(code **)(param_1->d_ino + 0xb8))(param_1,local_128);
                (**(code **)(param_1->d_ino + 0xb8))(param_1,local_118);
                pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x720))(param_1);
                local_95 = ((ulong)pdVar6 & 0xff) != 0;
                uVar4 = (x.588 + -1) * x.588;
                bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
                iVar1 = 0xfecb8cf;
                if (y.589 < 10 == bVar3 && (9 < y.589 || !bVar3)) {
                  iVar1 = 0x5b102eb5;
                }
              }
            }
            else if (iVar7 == -0x7b86ba96) {
              local_78 = local_1a8;
              iVar1 = 0x3ff13eb6;
              if (0xb < local_1a8) {
                iVar1 = 0x5c69feb4;
              }
            }
            else if (iVar7 == -0x7a2c5013) {
              pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x550))(param_1,local_f8,local_80);
              uVar4 = (x.588 + -1) * x.588 & 1;
              iVar1 = -0x6e854686;
              if (9 < y.589 == uVar4 && (9 < y.589 | uVar4) == 1) {
                iVar1 = -0x42e68bad;
              }
            }
          }
          else if (iVar7 < -0x756ff036) {
            if (iVar7 == -0x79f547b5) {
              pdVar6 = (dirent *)__android_log_print(6,&DAT_0013f18c,&DAT_0013fca0);
              iVar1 = -0x5eaddabc;
            }
            else if (iVar7 == -0x76023124) {
              (**(code **)(param_1->d_ino + 0xb8))(param_1,local_148);
              (**(code **)(param_1->d_ino + 0xb8))(param_1,local_158);
              (**(code **)(param_1->d_ino + 0xb8))(param_1,local_168);
              (**(code **)(param_1->d_ino + 0xb8))(param_1,local_170);
              pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0xb8))(param_1,local_188);
              iVar1 = -0x341b157e;
            }
          }
          else if (iVar7 == -0x756ff036) {
            iVar1 = -0x298316e7;
            if (pdVar2 != (dirent *)0x0) {
              iVar1 = -0x7474f1da;
            }
          }
          else if (iVar7 == -0x7474f1da) {
            pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0xf8))(param_1,DAT_00143b40);
            iVar1 = -0x15b0c31f;
            local_188 = pdVar6;
            if (pdVar6 != (dirent *)0x0) {
              iVar1 = -0x39a5a16;
            }
          }
          else if (iVar7 == -0x72f25727) {
            iVar1 = -0x76023124;
            if (local_8d == '\0') {
              iVar1 = -0x341b157e;
            }
          }
        }
        else if (iVar7 < -0x646ce11b) {
          if (iVar7 < -0x6ec57d00) {
            if (iVar7 == -0x7145c3e0) {
              pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x548))(param_1,local_f8,0);
              uVar4 = (x.588 + -1) * x.588;
              bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) != 0;
              iVar1 = 0x67c5d9d2;
              local_e8 = pdVar6;
              if (9 < y.589 == bVar3 && (9 < y.589 || bVar3)) {
                iVar1 = 0x6a6c4528;
              }
            }
            else if (iVar7 == -0x6f939220) {
              iVar1 = 0x271db537;
              if (local_149 == '\0') {
                iVar1 = -0x51e1a6d7;
              }
            }
          }
          else if (iVar7 == -0x6ec57d00) {
            iVar1 = -0x25b688f3;
            if (local_d0->d_type != '\b') {
              iVar1 = -0xd995a11;
            }
          }
          else {
            iVar1 = 0x5394626a;
            if ((iVar7 != -0x6e854686) && (iVar1 = iVar7, iVar7 == -0x68bbf383)) {
              pdVar6 = (dirent *)__android_log_print(6,&DAT_0013f18c,&DAT_0013fd10);
              uVar4 = (x.588 + -1) * x.588;
              bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) != 0;
              iVar1 = -0x396cedc4;
              if (9 < y.589 == bVar3 && (9 < y.589 || bVar3)) {
                iVar1 = 0x286988e5;
              }
            }
          }
        }
        else if (iVar7 < -0x5f6677e9) {
          if (iVar7 == -0x646ce11b) {
            (**(code **)(param_1->d_ino + 0xb8))(param_1,local_b0);
            pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0xb8))(param_1,local_a8);
            iVar1 = 0x6cb54976;
          }
          else if (iVar7 == -0x61b4b215) {
            pdVar6 = (dirent *)__android_log_print(6,&DAT_0013f18c,&DAT_0013fd70);
            uVar4 = (x.588 + -1) * x.588;
            bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
            iVar1 = 0x15610b8e;
            if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
              iVar1 = -0x5684a5b;
            }
          }
        }
        else if (iVar7 == -0x5f6677e9) {
          iVar1 = -0x11acd2c1;
          if (local_12d == '\0') {
            iVar1 = -0x16c8a7cc;
          }
        }
        else if (iVar7 == -0x5eaddabc) {
          pdVar6 = (dirent *)__android_log_print(6,&DAT_0013f18c,&DAT_0013fca0);
          uVar4 = (x.588 + -1) * x.588;
          bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
          iVar1 = -0x1286c20a;
          if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
            iVar1 = -0x79f547b5;
          }
        }
        else if (iVar7 == -0x5c90abf2) {
          local_1ac = 0;
          iVar1 = 0x3d071ebc;
        }
      }
      else if (iVar7 < -0x51a85956) {
        if (iVar7 < -0x54e25375) {
          if (iVar7 < -0x59ae0189) {
            if (iVar7 == -0x5b73fe66) {
              bVar3 = ((x.588 + -1) * x.588 & 1U) == 0;
              iVar1 = 0x6dfbb282;
              if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
                iVar1 = 0xeaa4fe0;
              }
            }
            else if (iVar7 == -0x5a7ddb0d) {
              iVar1 = -0x3376d704;
            }
          }
          else if (iVar7 == -0x59ae0189) {
            uVar4 = (x.588 + -1) * x.588;
            bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
            iVar1 = 0x7dc58bf7;
            if (y.589 < 10 == bVar3 && (9 < y.589 || !bVar3)) {
              iVar1 = -0x3c646f2a;
            }
          }
          else if (iVar7 == -0x58e6daef) {
            local_198 = 4;
            iVar1 = 0x6386fb7c;
          }
          else if (iVar7 == -0x57a98f09) {
            iVar1 = -0x7d706e86;
            if ((local_e9 & (local_80 != (dirent *)0x0 ^ local_e9 ^ 0xff) & 1) == 0) {
              iVar1 = -0x283e99a7;
            }
          }
        }
        else if (iVar7 < -0x52c57ca5) {
          if (iVar7 == -0x54e25375) {
            pdVar6 = (dirent *)opendir((char *)local_88);
            iVar1 = -0x5ddf82f;
            local_d8 = pdVar6;
            if (pdVar6 != (dirent *)0x0) {
              iVar1 = 0x470ec47f;
            }
          }
          else if (iVar7 == -0x53969f19) {
            iVar1 = -0x39cb56ba;
          }
        }
        else if (iVar7 == -0x52c57ca5) {
          bVar3 = local_70 == 0;
LAB_00115d1c:
          iVar1 = 0xd0c6a2e;
          if (!bVar3) {
            iVar1 = 0x31aa3236;
          }
        }
        else if (iVar7 == -0x522a782b) {
          bVar3 = ((x.588 + -1) * x.588 & 1U) == 0;
          iVar1 = 0x45e7ef1c;
          if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
            iVar1 = -0xe73ce70;
          }
        }
        else if (iVar7 == -0x51e1a6d7) {
          uVar4 = (x.588 + -1) * x.588 & 1;
          iVar1 = 0x2c7574a3;
          if (9 < y.589 == uVar4 && (9 < y.589 | uVar4) == 1) {
            iVar1 = 0x1f248965;
          }
        }
      }
      else if (iVar7 < -0x4662436e) {
        if (iVar7 < -0x4eab77a6) {
          if (iVar7 == -0x51a85956) {
            __android_log_print(4,&DAT_0013f18c,&DAT_0013fdd0,local_c8,local_80);
            DAT_00143938 = 1;
            strncpy(&DAT_00143939,local_c8,0xff);
            pdVar6 = (dirent *)strncpy(&DAT_00143a39,(char *)local_80,0xff);
            local_b1 = local_180 != (dirent *)0x0;
            uVar4 = (x.588 + -1) * x.588;
            bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
            iVar1 = 0x6ab5622;
            if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
              iVar1 = 0x758ef6e7;
            }
          }
          else if (iVar7 == -0x5084168b) {
            uVar4 = (x.588 + -1) * x.588;
            bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
            iVar1 = 0x3af318b4;
            if (y.589 < 10 == bVar3 && (9 < y.589 || !bVar3)) {
              iVar1 = 0x577ff43;
            }
          }
        }
        else if (iVar7 == -0x4eab77a6) {
          uVar4 = (x.588 + -1) * x.588 & 1;
          iVar1 = 0x26ffdab8;
          if (y.589 < 10 == (uVar4 == 0) && (9 < y.589 | uVar4) == 1) {
            iVar1 = 0x2517af24;
          }
        }
        else if (iVar7 == -0x4e062696) {
          uVar4 = closedir((DIR *)local_d8);
          pdVar6 = (dirent *)(ulong)uVar4;
          iVar1 = 0x212a2ec6;
        }
        else if (iVar7 == -0x47aaaabc) {
          pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x88))(param_1);
          iVar1 = 0x7179d075;
        }
      }
      else if (iVar7 < -0x426f4854) {
        if (iVar7 == -0x4662436e) {
          local_1b4 = local_1cc;
          iVar1 = 0x15689fa3;
          if (local_1cc != 7) {
            iVar1 = 0x662c2c7a;
          }
        }
        else if (iVar7 == -0x42e68bad) {
          pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x550))(param_1,local_f8,local_80);
          iVar1 = -0x7a2c5013;
        }
      }
      else if (iVar7 == -0x426f4854) {
        iVar1 = -0x25e91028;
      }
      else {
        iVar1 = 0x18cb01a2;
        if ((iVar7 != -0x4208b2a3) && (iVar1 = iVar7, iVar7 == -0x4131e16f)) {
          iVar1 = -0x39cb56ba;
        }
      }
    }
    if (-0x16c8a7cd < iVar7) {
      if (iVar7 < -0xb776e14) {
        if (iVar7 < -0x11acd2c1) {
          if (iVar7 < -0x15b0c31f) {
            if (iVar7 == -0x16c8a7cc) {
              pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x188))(param_1,local_158,local_140);
              local_1b0 = 0;
              local_12c = (int)pdVar6;
              iVar1 = 0x2891f687;
            }
            else if (iVar7 == -0x1689e66c) {
              local_1cc = 7;
              iVar1 = -0x4662436e;
            }
          }
          else if (iVar7 == -0x15b0c31f) {
            pdVar6 = (dirent *)__android_log_print(6,&DAT_0013f18c,&DAT_0013fb70);
            iVar1 = -0x38c32dca;
          }
          else if (iVar7 == -0x1286c20a) {
            iVar1 = 0x541c1837;
          }
        }
        else if (iVar7 < -0xe73ce70) {
          if (iVar7 == -0x11acd2c1) {
            uVar4 = (x.588 + -1) * x.588 & 1;
            iVar1 = -0x61b4b215;
            if (9 < y.589 == uVar4 && (9 < y.589 | uVar4) == 1) {
              iVar1 = -0x5684a5b;
            }
          }
          else if (iVar7 == -0x10106b61) {
            iVar1 = -0x58e6daef;
            if (local_119 == '\0') {
              iVar1 = 0x77d814ba;
            }
          }
        }
        else {
          iVar1 = -0x522a782b;
          if (((iVar7 != -0xe73ce70) && (iVar1 = 0x4ec7ebd5, iVar7 != -0xd995a11)) &&
             (iVar1 = iVar7, iVar7 == -0xc84b2ee)) {
            uVar4 = strcmp((char *)local_c0,&DAT_0013fdc0);
            pdVar6 = (dirent *)(ulong)uVar4;
            iVar1 = -0x37dd53a6;
            if (uVar4 != 0) {
              iVar1 = 0x15689fa3;
            }
          }
        }
      }
      else if (iVar7 < -0x4af647d) {
        if (iVar7 < -0xa039aa8) {
          if (iVar7 == -0xb776e14) {
            local_168 = (**(code **)(param_1->d_ino + 0xf8))(param_1,local_170);
            pdVar6 = (dirent *)
                     (**(code **)(param_1->d_ino + 0x108))
                               (param_1,local_168,&DAT_0013fcc0,&DAT_0013fa30);
            iVar1 = -0x5b73fe66;
            local_160 = pdVar6;
            if (pdVar6 != (dirent *)0x0) {
              iVar1 = 0x28f4f1b4;
            }
          }
          else if (iVar7 == -0xb298464) {
            pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x550))(param_1,local_100,local_88);
            iVar1 = -0x57a98f09;
          }
        }
        else if (iVar7 == -0xa039aa8) {
          pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x110))(param_1,local_170,local_160,0);
          local_149 = pdVar6 == (dirent *)0x0;
          uVar4 = (x.588 + -1) * x.588;
          bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
          iVar1 = -0x6f939220;
          local_158 = pdVar6;
          if (y.589 < 10 == bVar3 && (9 < y.589 || !bVar3)) {
            iVar1 = 0x40fd7684;
          }
        }
        else if (iVar7 == -0x5ddf82f) {
          local_1a4 = 0;
          iVar1 = 0x6346a926;
        }
        else if (iVar7 == -0x5684a5b) {
          pdVar6 = (dirent *)__android_log_print(6,&DAT_0013f18c,&DAT_0013fd70);
          iVar1 = -0x61b4b215;
        }
      }
      else if (iVar7 < -0x3bf7ba7) {
        if (iVar7 == -0x4af647d) {
          iVar1 = 0x3246a09e;
          if ((local_e9 & (local_80 != (dirent *)0x0 ^ local_e9 ^ 0xff) & 1) == 0) {
            iVar1 = 0x5394626a;
          }
        }
        else if (iVar7 == -0x47f8f0d) {
          uVar4 = (x.588 + -1) * x.588;
          bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
          iVar1 = -0x522a782b;
          if (y.589 < 10 == bVar3 && (9 < y.589 || !bVar3)) {
            iVar1 = -0xe73ce70;
          }
          local_74 = local_1a0;
        }
      }
      else if (iVar7 == -0x3bf7ba7) {
        pdVar6 = (dirent *)
                 (**(code **)(param_1->d_ino + 0x108))
                           (param_1,local_188,&DAT_0013fc20,&DAT_0013fc40);
        iVar1 = 0x186640e;
        local_178 = pdVar6;
        if (pdVar6 != (dirent *)0x0) {
          iVar1 = 0x3648217b;
        }
      }
      else if (iVar7 == -0x39a5a16) {
        pdVar6 = (dirent *)
                 (**(code **)(param_1->d_ino + 0x108))
                           (param_1,local_188,&DAT_0013fba0,&DAT_0013fbc0);
        iVar1 = 0x6e929da6;
        local_180 = pdVar6;
        if (pdVar6 != (dirent *)0x0) {
          iVar1 = -0x3bf7ba7;
        }
      }
      else if (iVar7 == -0x3210d4e) {
        iVar1 = -0x7474f1da;
      }
      goto LAB_00115d30;
    }
    if (iVar7 < -0x29eedbb1) {
      if (iVar7 < -0x38c32dca) {
        if (iVar7 < -0x3c646f2a) {
          if (iVar7 == -0x4083cec4) {
            pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x548))(param_1,local_100,0);
            iVar1 = 0x490643cd;
            local_1c8 = pdVar6;
          }
          else if (iVar7 == -0x40023964) {
            uVar4 = (x.588 + -1) * x.588 & 1;
            iVar1 = 0x11fdbab6;
            if (9 < y.589 == uVar4 && (9 < y.589 | uVar4) == 1) {
              iVar1 = 0x1c8a5567;
            }
          }
        }
        else {
          iVar1 = -0x59ae0189;
          if (((iVar7 != -0x3c646f2a) && (iVar1 = 0x541c1837, iVar7 != -0x39cb56ba)) &&
             (iVar1 = iVar7, iVar7 == -0x396cedc4)) {
            iVar1 = 0x7313b23;
          }
        }
      }
      else if (iVar7 < -0x341b157e) {
        if (iVar7 == -0x37dd53a6) {
          local_1a8 = 0;
          iVar1 = -0x7b86ba96;
        }
        else {
          if (iVar7 == -0x366917a7) {
            bVar3 = local_70 == 4;
            goto LAB_00115d1c;
          }
          if (iVar7 == -0x38c32dca) {
            return pdVar6;
          }
        }
      }
      else if (iVar7 == -0x341b157e) {
        bVar3 = ((x.588 + -1) * x.588 & 1U) == 0;
        iVar1 = -0x59ae0189;
        if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
          iVar1 = -0x3c646f2a;
        }
      }
      else if (iVar7 == -0x3376d704) {
        uVar4 = (x.588 + -1) * x.588;
        bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
        local_94 = local_8c + 1;
        iVar1 = 0x2de422c2;
        if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
          iVar1 = -0x5a7ddb0d;
        }
      }
    }
    else if (iVar7 < -0x24301b23) {
      if (iVar7 < -0x283e99a7) {
        if (iVar7 == -0x29eedbb1) {
          uVar4 = (x.588 + -1) * x.588 & 1;
          iVar1 = -0x1c1885a8;
          if (y.589 < 10 == (uVar4 == 0) && (9 < y.589 | uVar4) == 1) {
            iVar1 = 0x4034ef6b;
          }
        }
        else if (iVar7 == -0x298316e7) {
          uVar4 = (x.588 + -1) * x.588;
          bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
          iVar1 = 0x335dd063;
          if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
            iVar1 = -0x22e430b7;
          }
        }
      }
      else if (iVar7 == -0x283e99a7) {
        uVar4 = (x.588 + -1) * x.588;
        bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
        iVar1 = -0x7cc8f830;
        if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
          iVar1 = 0x5b102eb5;
        }
      }
      else if (iVar7 == -0x25e91028) {
        local_8d = local_6c == 2;
        bVar3 = ((x.588 + -1) * x.588 & 1U) == 0;
        iVar1 = -0x72f25727;
        if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
          iVar1 = -0x426f4854;
        }
      }
      else if (iVar7 == -0x25b688f3) {
        local_c8 = local_d0->d_name;
        pdVar6 = (dirent *)strrchr(local_c8,0x2e);
        iVar1 = 0x15689fa3;
        local_c0 = pdVar6;
        if (pdVar6 != (dirent *)0x0) {
          iVar1 = -0xc84b2ee;
        }
      }
    }
    else if (iVar7 < -0x20bc96ff) {
      if (iVar7 == -0x24301b23) {
        bVar3 = ((x.588 + -1) * x.588 & 1U) == 0;
        iVar1 = -0x7145c3e0;
        if ((y.589 >= 10 || !bVar3) && y.589 < 10 == bVar3) {
          iVar1 = 0x6a6c4528;
        }
      }
      else if (iVar7 == -0x22e430b7) {
        pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0xa8))(param_1,param_2);
        iVar1 = 0x335dd063;
        DAT_00143b40 = pdVar6;
      }
    }
    else if (iVar7 == -0x20bc96ff) {
      iVar1 = -0x52c57ca5;
      if (3 < local_70) {
        iVar1 = -0x366917a7;
      }
    }
    else if (iVar7 == -0x1c1885a8) {
      iVar1 = -0x20bc96ff;
    }
    else if (iVar7 == -0x1779f423) {
      pdVar6 = (dirent *)(**(code **)(param_1->d_ino + 0x110))(param_1,local_158,local_138,local_8c)
      ;
      local_119 = pdVar6 == (dirent *)0x0;
      uVar4 = (x.588 + -1) * x.588;
      bVar3 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
      iVar1 = -0x10106b61;
      local_128 = pdVar6;
      if (y.589 < 10 == bVar3 && (9 < y.589 || !bVar3)) {
        iVar1 = 0x502e0749;
      }
    }
  } while( true );
}

