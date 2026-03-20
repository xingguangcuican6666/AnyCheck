
uint Java_luna_safe_luna_MainActivity_findapply(long *param_1,undefined8 param_2)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  bool bVar5;
  int iVar6;
  char *pcVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  byte unaff_w24;
  int iVar11;
  byte local_c0;
  uint local_bc;
  int local_ac;
  uint local_a8;
  int local_a4;
  int local_a0;
  undefined8 local_98;
  int local_8c;
  undefined8 local_88;
  char *local_80;
  char local_72;
  char local_71;
  byte local_70;
  int local_6c;
  byte local_68;
  int local_64;
  
  bVar4 = (~((x.586 + -1) * x.586) | 0xfffffffeU) == 0xffffffff;
  bVar1 = y.587 < 10;
  iVar2 = -0x1c751ead;
LAB_00114f88:
  do {
    while( true ) {
      while (iVar6 = iVar2, iVar11 = -0xecdd71c, iVar2 = iVar11, iVar6 < -0x52c4b6e) {
        if (iVar6 < -0x2ac552b5) {
          if (iVar6 < -0x5a051a14) {
            if (iVar6 < -0x654ed65f) {
              if (iVar6 == -0x6a3fa2c9) {
                local_bc = 0;
                iVar2 = 0x5d019fb2;
              }
              else {
                iVar2 = iVar6;
                if (iVar6 == -0x68e3efc5) {
                  iVar2 = 0x135c16e1;
                }
              }
            }
            else if (iVar6 == -0x654ed65f) {
              bVar5 = ((x.586 + -1) * x.586 & 1U) == 0;
              iVar2 = 0x7ab0e0ed;
              if ((y.587 >= 10 || !bVar5) && y.587 < 10 == bVar5) {
                iVar2 = 0xc1ab2f7;
              }
            }
            else {
              iVar2 = iVar6;
              if (iVar6 == -0x5ca783c6) {
                iVar2 = -0x52c4b6e;
                if (3 < local_64) {
                  iVar2 = 0x78936930;
                }
              }
            }
          }
          else if (iVar6 < -0x48214f44) {
            if (iVar6 == -0x5a051a14) {
              uVar3 = (x.586 + -1) * x.586;
              bVar5 = ((uVar3 ^ 0xfffffffe) & uVar3) == 0;
              iVar2 = 0x135c16e1;
              if ((y.587 >= 10 || !bVar5) && y.587 < 10 == bVar5) {
                iVar2 = -0x68e3efc5;
              }
            }
            else {
              iVar2 = iVar6;
              if (iVar6 == -0x49a13d92) {
                iVar2 = -0x654ed65f;
                if (local_a4 != 2) {
                  iVar2 = 0x5d019fb2;
                }
                local_bc = local_a8;
              }
            }
          }
          else if (iVar6 == -0x48214f44) {
            iVar2 = -0x5ca783c6;
          }
          else {
            iVar2 = iVar6;
            if (iVar6 == -0x3093bd1f) {
              uVar3 = (x.586 + -1) * x.586;
              bVar5 = ((uVar3 ^ 0xfffffffe) & uVar3) == 0;
              iVar2 = 0x5b0aff6c;
              if (y.587 < 10 == bVar5 && (9 < y.587 || !bVar5)) {
                iVar2 = 0x660ae5fb;
              }
            }
          }
        }
        else if (iVar6 < -0x195167b1) {
          if (iVar6 < -0x1c751ead) {
            if (iVar6 == -0x2ac552b5) {
              local_a4 = local_64;
              local_a8 = (uint)local_68;
              iVar2 = -0x49a13d92;
            }
            else {
              iVar2 = iVar6;
              if (iVar6 == -0x1d62a5eb) {
                pcVar7 = strstr(local_80,&DAT_0013fb18);
                iVar2 = -0x3093bd1f;
                if (pcVar7 != (char *)0x0) {
                  iVar2 = iVar11;
                }
              }
            }
          }
          else if (iVar6 == -0x1c751ead) {
            iVar2 = -0xf9a7c0;
            if ((!bVar4 || !bVar1) && bVar4 == bVar1) {
              iVar2 = 0x7a306815;
            }
          }
          else {
            iVar2 = iVar6;
            if (iVar6 == -0x1a8816f2) {
              local_ac = 0;
              iVar2 = -0x195167b1;
            }
          }
        }
        else if (iVar6 < -0xa4575dc) {
          if (iVar6 == -0x195167b1) {
            local_6c = local_ac;
            iVar2 = 0x42dc38da;
            local_70 = local_c0;
            if (local_8c <= local_ac) {
              iVar2 = -0xa4575dc;
            }
          }
          else {
            iVar2 = iVar6;
            if (iVar6 == -0xecdd71c) {
              __android_log_print(4,&DAT_0013f18c,&DAT_0013fb30,local_80);
              (**(code **)(*param_1 + 0x550))(param_1,local_88,local_80);
              unaff_w24 = 1;
              local_a0 = 1;
              iVar2 = -0x877c774;
            }
          }
        }
        else if (iVar6 == -0xa4575dc) {
          local_a8 = (uint)local_70;
          local_a4 = 2;
          iVar2 = -0x49a13d92;
        }
        else if (iVar6 == -0x877c774) {
          local_64 = local_a0;
          uVar3 = (x.586 + -1) * x.586;
          bVar5 = ((uVar3 ^ 0xfffffffe) & uVar3) == 0;
          iVar2 = 0xbda82f9;
          local_68 = unaff_w24;
          if (y.587 < 10 == bVar5 && (9 < y.587 || !bVar5)) {
            iVar2 = -0x5de186c;
          }
        }
        else {
          iVar2 = iVar6;
          if (iVar6 == -0x5de186c) {
            iVar2 = 0xbda82f9;
          }
        }
      }
      if (0x429ce897 < iVar6) break;
      if (iVar6 < 0xc1ab2f7) {
        if (iVar6 < -0xf9a7c0) {
          if (iVar6 == -0x52c4b6e) {
            bVar5 = local_64 == 0;
LAB_00115730:
            iVar2 = -0x14e0dc3;
            if (!bVar5) {
              iVar2 = -0x2ac552b5;
            }
          }
          else {
            iVar2 = iVar6;
            if (iVar6 == -0x14e0dc3) {
              local_ac = local_6c + 1;
              iVar2 = -0x195167b1;
              local_c0 = local_68;
            }
          }
        }
        else if (iVar6 == -0xf9a7c0) {
          __android_log_print(4,&DAT_0013f18c,&DAT_0013f930);
          uVar8 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f950);
          uVar9 = (**(code **)(*param_1 + 0x108))(param_1,uVar8,&DAT_0013f970,&DAT_0013f990);
          uVar10 = (**(code **)(*param_1 + 0x480))(param_1,uVar8,&DAT_0013f9c0,&DAT_0013f9e0);
          uVar8 = (**(code **)(*param_1 + 0x488))(param_1,uVar8,uVar10);
          uVar8 = (**(code **)(*param_1 + 0x110))(param_1,param_2,uVar9,uVar8);
          uVar9 = (**(code **)(*param_1 + 0xf8))(param_1,uVar8);
          uVar9 = (**(code **)(*param_1 + 0x108))(param_1,uVar9,&DAT_0013fa00,&DAT_0013fa30);
          uVar8 = (**(code **)(*param_1 + 0x110))(param_1,uVar8,uVar9,1);
          uVar9 = (**(code **)(*param_1 + 0xf8))(param_1,uVar8);
          uVar9 = (**(code **)(*param_1 + 0x108))(param_1,uVar9,&DAT_0013fa48,&DAT_0013fa50);
          local_98 = (**(code **)(*param_1 + 0x110))(param_1,uVar8,uVar9);
          local_8c = (**(code **)(*param_1 + 0x558))(param_1,local_98);
          uVar3 = (x.586 + -1) * x.586 & 1;
          iVar2 = -0x1a8816f2;
          if (9 < y.587 == uVar3 && (9 < y.587 | uVar3) == 1) {
            iVar2 = 0x7a306815;
          }
        }
        else {
          iVar2 = iVar6;
          if (iVar6 == 0xbda82f9) {
            uVar3 = (x.586 + -1) * x.586;
            bVar5 = ((uVar3 ^ 0xfffffffe) & uVar3) == 0;
            iVar2 = -0x48214f44;
            if ((y.587 >= 10 || !bVar5) && y.587 < 10 == bVar5) {
              iVar2 = -0x5de186c;
            }
          }
        }
      }
      else if (iVar6 < 0x35022114) {
        iVar2 = 0x7ab0e0ed;
        if ((iVar6 != 0xc1ab2f7) && (iVar2 = iVar6, iVar6 == 0x135c16e1)) {
          pcVar7 = strstr(local_80,&DAT_0013fb28);
          local_71 = pcVar7 != (char *)0x0;
          uVar3 = (x.586 + -1) * x.586;
          bVar5 = ((uVar3 ^ 0xfffffffe) & uVar3) == 0;
          iVar2 = 0x429ce898;
          if ((y.587 >= 10 || !bVar5) && y.587 < 10 == bVar5) {
            iVar2 = -0x68e3efc5;
          }
        }
      }
      else if (iVar6 == 0x35022114) {
        if (local_72 == '\0') {
          iVar2 = -0x5a051a14;
        }
      }
      else {
        iVar2 = iVar6;
        if (iVar6 == 0x4156cd1b) {
          (**(code **)(*param_1 + 0x550))(param_1,local_88,local_80);
          local_a0 = 0;
LAB_00114f7c:
          iVar2 = -0x877c774;
          unaff_w24 = local_70;
        }
      }
    }
    if (0x7698a388 < iVar6) {
      if (iVar6 < 0x7a306815) {
        if (iVar6 == 0x7698a389) {
          local_a0 = 4;
          __android_log_print(4,&DAT_0013f18c,&DAT_0013fb00,local_80);
          (**(code **)(*param_1 + 0x550))(param_1,local_88,local_80);
          goto LAB_00114f7c;
        }
        iVar2 = iVar6;
        if (iVar6 == 0x78936930) {
          bVar5 = local_64 == 4;
          goto LAB_00115730;
        }
      }
      else if (iVar6 == 0x7a306815) {
        __android_log_print(4,&DAT_0013f18c,&DAT_0013f930);
        uVar8 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f950);
        uVar9 = (**(code **)(*param_1 + 0x108))(param_1,uVar8,&DAT_0013f970,&DAT_0013f990);
        uVar10 = (**(code **)(*param_1 + 0x480))(param_1,uVar8,&DAT_0013f9c0,&DAT_0013f9e0);
        uVar8 = (**(code **)(*param_1 + 0x488))(param_1,uVar8,uVar10);
        uVar8 = (**(code **)(*param_1 + 0x110))(param_1,param_2,uVar9,uVar8);
        uVar9 = (**(code **)(*param_1 + 0xf8))(param_1,uVar8);
        uVar9 = (**(code **)(*param_1 + 0x108))(param_1,uVar9,&DAT_0013fa00,&DAT_0013fa30);
        uVar8 = (**(code **)(*param_1 + 0x110))(param_1,uVar8,uVar9,1);
        uVar9 = (**(code **)(*param_1 + 0xf8))(param_1,uVar8);
        uVar9 = (**(code **)(*param_1 + 0x108))(param_1,uVar9,&DAT_0013fa48,&DAT_0013fa50);
        uVar8 = (**(code **)(*param_1 + 0x110))(param_1,uVar8,uVar9);
        (**(code **)(*param_1 + 0x558))(param_1,uVar8);
        iVar2 = -0xf9a7c0;
      }
      else {
        iVar2 = iVar6;
        if (iVar6 == 0x7ab0e0ed) {
          uVar3 = (x.586 + -1) * x.586;
          bVar5 = ((uVar3 ^ 0xfffffffe) & uVar3) != 0;
          iVar2 = -0x6a3fa2c9;
          if (9 < y.587 == bVar5 && (9 < y.587 || bVar5)) {
            iVar2 = 0xc1ab2f7;
          }
        }
      }
      goto LAB_00114f88;
    }
    if (iVar6 < 0x5b0aff6c) {
      if (iVar6 == 0x429ce898) {
        if (local_71 == '\0') {
          iVar2 = 0x4156cd1b;
        }
      }
      else {
        iVar2 = iVar6;
        if (iVar6 == 0x42dc38da) {
          uVar8 = (**(code **)(*param_1 + 0x568))(param_1,local_98,local_6c);
          uVar9 = (**(code **)(*param_1 + 0xf8))(param_1,uVar8);
          uVar9 = (**(code **)(*param_1 + 0x108))(param_1,uVar9,&DAT_0013fa68,&DAT_0013fa70);
          local_88 = (**(code **)(*param_1 + 0x110))(param_1,uVar8,uVar9);
          local_80 = (char *)(**(code **)(*param_1 + 0x548))(param_1,local_88,0);
          __android_log_print(4,&DAT_0013f18c,&DAT_0013fa90,local_80);
          iVar6 = strcmp(local_80,&DAT_0013fab0);
          iVar2 = 0x7698a389;
          if (iVar6 != 0) {
            iVar2 = -0x1d62a5eb;
          }
        }
      }
    }
    else if (iVar6 == 0x5b0aff6c) {
      pcVar7 = strstr(local_80,&DAT_0013fb20);
      local_72 = pcVar7 != (char *)0x0;
      uVar3 = (x.586 + -1) * x.586;
      bVar5 = ((uVar3 ^ 0xfffffffe) & uVar3) != 0;
      iVar2 = 0x35022114;
      if (9 < y.587 == bVar5 && (9 < y.587 || bVar5)) {
        iVar2 = 0x660ae5fb;
      }
    }
    else if (iVar6 == 0x660ae5fb) {
      iVar2 = 0x5b0aff6c;
    }
    else {
      iVar2 = iVar6;
      if (iVar6 == 0x5d019fb2) {
        return local_bc;
      }
    }
  } while( true );
}

