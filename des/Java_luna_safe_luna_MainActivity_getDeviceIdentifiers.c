
undefined8
Java_luna_safe_luna_MainActivity_getDeviceIdentifiers
          (long *param_1,undefined8 param_2,undefined8 param_3)

{
  uint uVar1;
  undefined1 auVar2 [16];
  undefined1 auVar3 [16];
  int iVar4;
  bool bVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  undefined8 extraout_x1;
  undefined8 extraout_x1_00;
  undefined8 extraout_x1_01;
  undefined8 extraout_x1_02;
  undefined8 extraout_x1_03;
  undefined8 extraout_x1_04;
  undefined8 extraout_x1_05;
  undefined8 extraout_x1_06;
  int iVar9;
  undefined8 unaff_x23;
  code *pcVar10;
  undefined1 auVar11 [16];
  undefined1 auVar12 [16];
  undefined8 local_130;
  undefined8 local_128;
  undefined1 auStack_11c [92];
  undefined1 *local_c0;
  undefined1 *local_b8;
  int local_ac;
  undefined8 local_a8;
  ulong local_a0;
  char local_91;
  long local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  
  local_c0 = auStack_11c;
  local_b8 = local_c0;
  local_ac = __system_property_get(&DAT_0013f4c8,local_c0);
  auVar11._8_8_ = extraout_x1;
  auVar11._0_8_ = local_88;
  iVar4 = 0x43b371bb;
  do {
    while( true ) {
      while( true ) {
        iVar9 = iVar4;
        local_88 = auVar11._0_8_;
        iVar4 = iVar9;
        if (iVar9 < -0x8963239) break;
        if (iVar9 < 0x43d78523) {
          if (iVar9 < 0x12992e80) {
            if (iVar9 == -0x8963239) {
              iVar4 = -0x27fa499e;
              if (local_91 == '\0') {
                iVar4 = -0xb6e172;
              }
            }
            else if (iVar9 == -0xb6e172) {
              __android_log_print(3,&DAT_0013e9f8,&DAT_0013f520);
              uVar6 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f550);
              param_3 = (**(code **)(*param_1 + 0x388))(param_1,uVar6,&DAT_0013f578,&DAT_0013f590);
              uVar7 = (**(code **)(*param_1 + 0xf8))(param_1,param_2);
              uVar7 = (**(code **)(*param_1 + 0x108))(param_1,uVar7,&DAT_0013f5e0,&DAT_0013f600);
              uVar7 = (**(code **)(*param_1 + 0x110))(param_1,param_2,uVar7);
              uVar8 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_0013f628);
              auVar12 = (**(code **)(*param_1 + 0x390))(param_1,uVar6,param_3,uVar7,uVar8);
              auVar3._8_8_ = auVar12._8_8_;
              auVar3._0_8_ = local_88;
              auVar11._8_8_ = auVar12._8_8_;
              auVar11._0_8_ = local_88;
              local_90 = auVar12._0_8_;
              iVar4 = -0x63f210de;
              if (local_90 != 0) {
                iVar4 = -0x73034e21;
                auVar11 = auVar3;
              }
            }
            else if (iVar9 == 0x4917ae) {
              local_130 = local_88;
              iVar4 = -0x5ca4b268;
            }
          }
          else if (iVar9 < 0x2d270705) {
            if (iVar9 == 0x12992e80) {
              local_a0 = getMediaDrmId(param_1,auVar11._8_8_,param_3);
              auVar12._8_8_ = extraout_x1_03;
              auVar12._0_8_ = local_88;
              auVar11._8_8_ = extraout_x1_03;
              auVar11._0_8_ = local_88;
              local_91 = local_a0 != 0;
              uVar1 = (x.552 + -1) * x.552 & 1;
              iVar4 = -0x8963239;
              if (9 < y.553 == uVar1 && (9 < y.553 | uVar1) == 1) {
                iVar4 = 0x43d78523;
                auVar11 = auVar12;
              }
            }
            else if (iVar9 == 0x26c47996) {
              pcVar10 = *(code **)(*param_1 + 0x560);
              param_3 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
              uVar6 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_001051d1);
              auVar11 = (*pcVar10)(param_1,0,param_3,uVar6);
              uVar1 = (x.552 + -1) * x.552;
              bVar5 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
              iVar4 = 0x4917ae;
              if ((y.553 >= 10 || !bVar5) && y.553 < 10 == bVar5) {
                iVar4 = 0x6cad782f;
              }
            }
          }
          else {
            iVar4 = 0x74e8b277;
            if ((iVar9 != 0x2d270705) && (iVar4 = iVar9, iVar9 == 0x43b371bb)) {
              iVar4 = -0x229c7394;
              if (local_ac < 1) {
                iVar4 = -0x7209b46f;
              }
            }
          }
        }
        else if (iVar9 < 0x563ed140) {
          if (iVar9 == 0x43d78523) {
            getMediaDrmId(param_1,auVar11._8_8_,param_3);
            auVar11._8_8_ = extraout_x1_05;
            auVar11._0_8_ = local_88;
            iVar4 = 0x12992e80;
          }
          else if (iVar9 == 0x449ec166) {
            __android_log_print(3,&DAT_0013e9f8,&DAT_0013f4e0,local_b8);
            pcVar10 = *(code **)(*param_1 + 0x560);
            uVar6 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
            uVar7 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_001051d1);
            local_a8 = (*pcVar10)(param_1,1,uVar6,uVar7);
            pcVar10 = *(code **)(*param_1 + 0x570);
            uVar6 = (**(code **)(*param_1 + 0x538))(param_1,local_b8);
            param_3 = 0;
            (*pcVar10)(param_1,local_a8,0,uVar6);
            auVar2._8_8_ = extraout_x1_06;
            auVar2._0_8_ = local_88;
            auVar11._8_8_ = extraout_x1_06;
            auVar11._0_8_ = local_88;
            uVar1 = (x.552 + -1) * x.552;
            bVar5 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
            iVar4 = -0x4a8f1021;
            if (y.553 < 10 == bVar5 && (9 < y.553 || !bVar5)) {
              iVar4 = -0x4980f38f;
              auVar11 = auVar2;
            }
          }
          else if (iVar9 == 0x505a2cd4) {
            iVar4 = -0x6ad5befd;
          }
        }
        else if (iVar9 < 0x6cad782f) {
          uVar6 = local_78;
          if (iVar9 == 0x629fe580) goto LAB_0010b178;
          if (iVar9 == 0x563ed140) {
            return local_70;
          }
        }
        else if (iVar9 == 0x6cad782f) {
          pcVar10 = *(code **)(*param_1 + 0x560);
          param_3 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
          uVar6 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_001051d1);
          (*pcVar10)(param_1,0,param_3,uVar6);
          auVar11._8_8_ = extraout_x1_00;
          auVar11._0_8_ = local_88;
          iVar4 = 0x26c47996;
        }
        else if (iVar9 == 0x74e8b277) {
          uVar1 = (x.552 + -1) * x.552;
          bVar5 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
          iVar4 = -0x65cd4dc7;
          if (y.553 < 10 == bVar5 && (9 < y.553 || !bVar5)) {
            iVar4 = 0x2d270705;
          }
        }
      }
      if (-0x4f625dbd < iVar9) break;
      if (iVar9 < -0x6ad5befd) {
        if (iVar9 == -0x73034e21) {
          param_3 = (**(code **)(*param_1 + 0x548))(param_1,local_90,0);
          __system_property_set(&DAT_0013f4c8,param_3);
          __android_log_print(3,&DAT_0013e9f8,&DAT_0013f640,param_3);
          pcVar10 = *(code **)(*param_1 + 0x560);
          uVar6 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
          uVar7 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_001051d1);
          local_130 = (*pcVar10)(param_1,1,uVar6,uVar7);
          (**(code **)(*param_1 + 0x570))(param_1,local_130,0,local_90);
          (**(code **)(*param_1 + 0x550))(param_1,local_90);
          auVar11._8_8_ = extraout_x1_04;
          auVar11._0_8_ = local_88;
          iVar4 = -0x5ca4b268;
        }
        else if (iVar9 == -0x7209b46f) {
          bVar5 = ((x.552 + -1) * x.552 & 1U) == 0;
          iVar4 = 0x12992e80;
          if ((y.553 >= 10 || !bVar5) && y.553 < 10 == bVar5) {
            iVar4 = 0x43d78523;
          }
        }
        else if (iVar9 == -0x704d258f) {
          uVar1 = (x.552 + -1) * x.552;
          bVar5 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
          iVar4 = 0x563ed140;
          if (9 < y.553 == bVar5 && (9 < y.553 || bVar5)) {
            iVar4 = -0xcf5edaa;
          }
        }
      }
      else if (iVar9 < -0x63f210de) {
        if (iVar9 == -0x6ad5befd) {
          uVar1 = (x.552 + -1) * x.552;
          bVar5 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
          iVar4 = 0x629fe580;
          if (y.553 < 10 == bVar5 && (9 < y.553 || !bVar5)) {
            iVar4 = 0x505a2cd4;
          }
        }
        else if (iVar9 == -0x65cd4dc7) {
          unaff_x23 = local_80;
          iVar4 = -0x31369f79;
        }
      }
      else if (iVar9 == -0x63f210de) {
        bVar5 = ((x.552 + -1) * x.552 & 1U) == 0;
        iVar4 = 0x26c47996;
        if ((y.553 >= 10 || !bVar5) && y.553 < 10 == bVar5) {
          iVar4 = 0x6cad782f;
        }
      }
      else if (iVar9 == -0x5ca4b268) {
        local_80 = local_130;
        uVar1 = (x.552 + -1) * x.552;
        bVar5 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
        iVar4 = 0x74e8b277;
        if ((y.553 >= 10 || !bVar5) && y.553 < 10 == bVar5) {
          iVar4 = 0x2d270705;
        }
      }
    }
    if (iVar9 < -0x31369f79) {
      if (iVar9 == -0x4f625dbc) {
        local_70 = local_128;
        uVar1 = (x.552 + -1) * x.552;
        bVar5 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
        iVar4 = -0x704d258f;
        if (y.553 < 10 == bVar5 && (9 < y.553 || !bVar5)) {
          iVar4 = -0xcf5edaa;
        }
      }
      else {
        uVar6 = local_a8;
        if (iVar9 == -0x4a8f1021) {
LAB_0010b178:
          iVar4 = -0x4f625dbc;
          local_128 = uVar6;
        }
        else if (iVar9 == -0x4980f38f) {
          __android_log_print(3,&DAT_0013e9f8,&DAT_0013f4e0,local_b8);
          pcVar10 = *(code **)(*param_1 + 0x560);
          uVar6 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
          uVar7 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_001051d1);
          uVar6 = (*pcVar10)(param_1,1,uVar6,uVar7);
          pcVar10 = *(code **)(*param_1 + 0x570);
          uVar7 = (**(code **)(*param_1 + 0x538))(param_1,local_b8);
          param_3 = 0;
          (*pcVar10)(param_1,uVar6,0,uVar7);
          auVar11._8_8_ = extraout_x1_02;
          auVar11._0_8_ = local_88;
          iVar4 = 0x449ec166;
        }
      }
    }
    else if (iVar9 < -0x229c7394) {
      if (iVar9 == -0x31369f79) {
        uVar1 = (x.552 + -1) * x.552;
        bVar5 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
        iVar4 = -0x6ad5befd;
        local_78 = unaff_x23;
        if (9 < y.553 == bVar5 && (9 < y.553 || bVar5)) {
          iVar4 = 0x505a2cd4;
        }
      }
      else if (iVar9 == -0x27fa499e) {
        param_3 = (**(code **)(*param_1 + 0x548))(param_1,local_a0,0);
        __system_property_set(&DAT_0013f4c8,param_3);
        __android_log_print(3,&DAT_0013e9f8,&DAT_0013f500,param_3);
        pcVar10 = *(code **)(*param_1 + 0x560);
        uVar6 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
        uVar7 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_001051d1);
        unaff_x23 = (*pcVar10)(param_1,1,uVar6,uVar7);
        (**(code **)(*param_1 + 0x570))(param_1,unaff_x23,0,local_a0);
        (**(code **)(*param_1 + 0x550))(param_1,local_a0);
        (**(code **)(*param_1 + 0xb8))(param_1,local_a0);
        auVar11._8_8_ = extraout_x1_01;
        auVar11._0_8_ = local_88;
        iVar4 = -0x31369f79;
      }
    }
    else if (iVar9 == -0x229c7394) {
      bVar5 = ((x.552 + -1) * x.552 & 1U) == 0;
      iVar4 = 0x449ec166;
      if ((y.553 >= 10 || !bVar5) && y.553 < 10 == bVar5) {
        iVar4 = -0x4980f38f;
      }
    }
    else if (iVar9 == -0xcf5edaa) {
      iVar4 = -0x704d258f;
    }
  } while( true );
}

