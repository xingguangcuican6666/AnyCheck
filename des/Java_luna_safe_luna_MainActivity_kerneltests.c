
undefined8
Java_luna_safe_luna_MainActivity_kerneltests(long *param_1,undefined8 param_2,undefined8 param_3)

{
  uint uVar1;
  int iVar2;
  bool bVar3;
  undefined8 uVar4;
  time_t tVar5;
  int iVar6;
  code *pcVar7;
  char acStack_4e8 [512];
  char acStack_2e8 [256];
  char acStack_1e8 [256];
  long local_e8;
  long local_e0;
  long local_d8;
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
  
  local_e8 = (**(code **)(*param_1 + 0xf8))();
  iVar2 = -0x755e2db6;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          while (iVar6 = iVar2, iVar2 = iVar6, iVar6 < -0x1e87d7a4) {
            if (iVar6 < -0x551c660c) {
              if (iVar6 < -0x60f2af26) {
                if (iVar6 < -0x755e2db6) {
                  if (iVar6 == -0x7e986b35) {
                    pcVar7 = *(code **)(*param_1 + 0x1e8);
                    uVar4 = (**(code **)(*param_1 + 0x538))(param_1,local_78);
                    (*pcVar7)(param_1,param_2,local_70,uVar4);
                    (**(code **)(*param_1 + 0x550))(param_1,local_d0,local_c8);
                    (**(code **)(*param_1 + 0x550))(param_1,local_a0,local_98);
                    (**(code **)(*param_1 + 0x550))(param_1,param_3,local_88);
                    uVar1 = (x.582 + -1) * x.582;
                    bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                    iVar2 = -0x5afc2e0;
                    if (y.583 < 10 == bVar3 && (9 < y.583 || !bVar3)) {
                      iVar2 = -0x3ed0cb75;
                    }
                  }
                  else if (iVar6 == -0x7b065fab) {
                    iVar2 = -0x50e00a60;
                  }
                }
                else if (iVar6 == -0x755e2db6) {
                  iVar2 = -0x28aa437b;
                  if (local_e8 != 0) {
                    iVar2 = -0x101f4879;
                  }
                }
                else if (iVar6 == -0x7532f008) {
                  iVar2 = -0x1c5cd399;
                }
                else if (iVar6 == -0x742e2991) {
                  uVar1 = (x.582 + -1) * x.582;
                  bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
                  iVar2 = 0x298a4076;
                  if (9 < y.583 == bVar3 && (9 < y.583 || bVar3)) {
                    iVar2 = -0x5df996d6;
                  }
                }
              }
              else if (iVar6 < -0x5df996d6) {
                iVar2 = -0x173c4315;
                if ((iVar6 != -0x60f2af26) && (iVar2 = iVar6, iVar6 == -0x5e28b459)) {
                  local_c8 = (**(code **)(*param_1 + 0x548))(param_1,local_d0,0);
                  iVar2 = -0x2ca83054;
                  if (local_c8 != 0) {
                    iVar2 = -0x593e72cd;
                  }
                }
              }
              else {
                iVar2 = -0x742e2991;
                if (((iVar6 != -0x5df996d6) && (iVar2 = 0x4cc65ccf, iVar6 != -0x5c1131f1)) &&
                   (iVar2 = iVar6, iVar6 == -0x593e72cd)) {
                  uVar1 = (x.582 + -1) * x.582;
                  bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                  iVar2 = -0x1a44c87d;
                  if (y.583 < 10 == bVar3 && (9 < y.583 || !bVar3)) {
                    iVar2 = -0x2f04e2ef;
                  }
                }
              }
            }
            else if (iVar6 < -0x3377ab32) {
              if (iVar6 < -0x4f61d1f9) {
                if (iVar6 == -0x551c660c) {
                  local_90 = acStack_2e8;
                  snprintf(acStack_2e8,0x100,(char *)&DAT_0013f7f8,local_90,local_98);
                  local_88 = (**(code **)(*param_1 + 0x548))(param_1,param_3,0);
                  local_80 = acStack_4e8;
                  local_78 = local_80;
                  snprintf(local_80,0x200,&DAT_0013f798,local_80,local_88,acStack_2e8);
                  local_70 = (**(code **)(*param_1 + 0x108))
                                       (param_1,local_e8,&DAT_0013f7a0,&DAT_0013f7c0);
                  iVar2 = -0x231552f6;
                  if (local_70 != 0) {
                    iVar2 = 0x6730ce7a;
                  }
                }
                else if (iVar6 == -0x50e00a60) {
                  iVar2 = -0x1741ecc1;
                }
              }
              else {
                iVar2 = -0x1741ecc1;
                if (iVar6 != -0x4f61d1f9) {
                  if (iVar6 == -0x456732f1) {
                    uVar4 = (**(code **)(*param_1 + 0x538))(param_1,local_b8);
                    local_a0 = (**(code **)(*param_1 + 0x110))(param_1,param_2,local_b0,uVar4);
                    iVar2 = -0x32e68f0d;
                    if (local_a0 != 0) {
                      iVar2 = -0x1e87d7a4;
                    }
                  }
                  else {
                    iVar2 = iVar6;
                    if (iVar6 == -0x3ed0cb75) {
                      pcVar7 = *(code **)(*param_1 + 0x1e8);
                      uVar4 = (**(code **)(*param_1 + 0x538))(param_1,local_78);
                      (*pcVar7)(param_1,param_2,local_70,uVar4);
                      (**(code **)(*param_1 + 0x550))(param_1,local_d0,local_c8);
                      (**(code **)(*param_1 + 0x550))(param_1,local_a0,local_98);
                      (**(code **)(*param_1 + 0x550))(param_1,param_3,local_88);
                      iVar2 = -0x7e986b35;
                    }
                  }
                }
              }
            }
            else if (iVar6 < -0x2ca83054) {
              if (iVar6 == -0x3377ab32) {
                local_d8 = (**(code **)(*param_1 + 0x110))(param_1,param_2,local_e0);
                iVar2 = 0x23d415de;
                if (local_d8 != 0) {
                  iVar2 = 0x248622b6;
                }
              }
              else if (iVar6 == -0x32e68f0d) {
                uVar1 = (x.582 + -1) * x.582 & 1;
                iVar2 = -0x742e2991;
                if (y.583 < 10 == (uVar1 == 0) && (9 < y.583 | uVar1) == 1) {
                  iVar2 = -0x5df996d6;
                }
              }
              else if (iVar6 == -0x2f04e2ef) {
                tVar5 = time((time_t *)0x0);
                snprintf(acStack_1e8,0x100,&DAT_0013f890,local_c8,tVar5);
                (**(code **)(*param_1 + 0x108))(param_1,local_e8,&DAT_0013f750,&DAT_0013f760);
                iVar2 = -0x1a44c87d;
              }
            }
            else {
              iVar2 = 0x660616ff;
              if (((iVar6 != -0x2ca83054) && (iVar2 = 0x4cc65ccf, iVar6 != -0x28aa437b)) &&
                 (iVar2 = iVar6, iVar6 == -0x231552f6)) {
                iVar2 = -0x7532f008;
              }
            }
          }
          if (0x1a0d2734 < iVar6) break;
          if (iVar6 < -0x173c4315) {
            if (iVar6 < -0x1a44c87d) {
              if (iVar6 == -0x1e87d7a4) {
                local_98 = (**(code **)(*param_1 + 0x548))(param_1,local_a0,0);
                iVar2 = 0x3070ba94;
                if (local_98 != 0) {
                  iVar2 = -0x551c660c;
                }
              }
              else if ((iVar6 == -0x1c5cd399) &&
                      (uVar1 = (x.582 + -1) * x.582, bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0,
                      iVar2 = -0x173c4315, (y.583 >= 10 || !bVar3) && y.583 < 10 == bVar3)) {
                iVar2 = -0x60f2af26;
              }
            }
            else if (iVar6 == -0x1a44c87d) {
              tVar5 = time((time_t *)0x0);
              local_c0 = acStack_1e8;
              local_b8 = local_c0;
              snprintf(local_c0,0x100,&DAT_0013f890,local_c8,tVar5);
              local_b0 = (**(code **)(*param_1 + 0x108))
                                   (param_1,local_e8,&DAT_0013f750,&DAT_0013f760);
              local_a1 = local_b0 == 0;
              uVar1 = (x.582 + -1) * x.582;
              bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
              iVar2 = -0x10d16c2;
              if ((y.583 >= 10 || !bVar3) && y.583 < 10 == bVar3) {
                iVar2 = -0x2f04e2ef;
              }
            }
            else if (iVar6 == -0x17919fab) {
              uVar1 = (x.582 + -1) * x.582;
              bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
              iVar2 = 0x5f28f026;
              if (y.583 < 10 == bVar3 && (9 < y.583 || !bVar3)) {
                iVar2 = 0x5c727e88;
              }
            }
            else if (iVar6 == -0x1741ecc1) {
              iVar2 = 0x660616ff;
            }
          }
          else if (iVar6 < -0x5afc2e0) {
            if (iVar6 == -0x173c4315) {
              uVar1 = (x.582 + -1) * x.582;
              bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
              iVar2 = -0x7b065fab;
              if (9 < y.583 == bVar3 && (9 < y.583 || bVar3)) {
                iVar2 = -0x60f2af26;
              }
            }
            else if (iVar6 == -0x101f4879) {
              local_e0 = (**(code **)(*param_1 + 0x108))
                                   (param_1,local_e8,&DAT_0013f700,&DAT_0013f720);
              iVar2 = -0x17919fab;
              if (local_e0 != 0) {
                iVar2 = -0x3377ab32;
              }
            }
            else if (iVar6 == -0x6d8efe9) {
              iVar2 = 0xd09202a;
            }
          }
          else {
            iVar2 = -0x7532f008;
            if (iVar6 != -0x5afc2e0) {
              if (iVar6 == -0x10d16c2) {
                iVar2 = -0x4f61d1f9;
                if (local_a1 == '\0') {
                  iVar2 = -0x456732f1;
                }
              }
              else {
                iVar2 = iVar6;
                if (iVar6 == 0xd09202a) {
                  iVar2 = -0x5c1131f1;
                }
              }
            }
          }
        }
        if (0x3070ba93 < iVar6) break;
        if (iVar6 < 0x23d415de) {
          iVar2 = -0x5c1131f1;
          if ((iVar6 != 0x1a0d2735) && (iVar2 = iVar6, iVar6 == 0x2049499a)) {
            iVar2 = -0x6d8efe9;
          }
        }
        else {
          iVar2 = 0xd09202a;
          if (iVar6 != 0x23d415de) {
            if (iVar6 == 0x248622b6) {
              local_d0 = (**(code **)(*param_1 + 0x568))(param_1,local_d8,0);
              iVar2 = 0x2049499a;
              if (local_d0 != 0) {
                iVar2 = -0x5e28b459;
              }
            }
            else {
              iVar2 = iVar6;
              if (iVar6 == 0x298a4076) {
                iVar2 = -0x50e00a60;
              }
            }
          }
        }
      }
      if (iVar6 < 0x5f28f026) break;
      if (iVar6 == 0x5f28f026) {
        uVar1 = (x.582 + -1) * x.582;
        bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
        iVar2 = 0x1a0d2735;
        if (9 < y.583 == bVar3 && (9 < y.583 || bVar3)) {
          iVar2 = 0x5c727e88;
        }
      }
      else {
        iVar2 = -0x6d8efe9;
        if ((iVar6 != 0x660616ff) && (iVar2 = iVar6, iVar6 == 0x6730ce7a)) {
          uVar1 = (x.582 + -1) * x.582;
          bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
          iVar2 = -0x7e986b35;
          if (9 < y.583 == bVar3 && (9 < y.583 || bVar3)) {
            iVar2 = -0x3ed0cb75;
          }
        }
      }
    }
    iVar2 = -0x1c5cd399;
  } while (((iVar6 == 0x3070ba94) || (iVar2 = 0x5f28f026, iVar6 == 0x5c727e88)) ||
          (iVar2 = iVar6, iVar6 != 0x4cc65ccf));
  return 0;
}

