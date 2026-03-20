
undefined8 Java_luna_safe_luna_MainActivity_checknum(long *param_1)

{
  uint uVar1;
  int iVar2;
  bool bVar3;
  int iVar4;
  undefined8 unaff_x21;
  undefined1 auStack_e4 [92];
  undefined1 *local_88;
  undefined1 *local_80;
  int local_74;
  undefined8 local_70;
  undefined8 local_68;
  
  local_88 = auStack_e4;
  local_80 = local_88;
  local_74 = __system_property_get(&DAT_00140210,local_88);
  __android_log_print(3,&DAT_001401c8,&DAT_00140240,local_80);
  iVar2 = 0x30eb2ad3;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          while (iVar4 = iVar2, iVar2 = iVar4, 0x1448f369 < iVar4) {
            if (iVar4 < 0x3adaec18) {
              if (iVar4 == 0x1448f36a) {
                uVar1 = (x.604 + -1) * x.604;
                bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                iVar2 = 0x4ef970d9;
                if ((y.605 >= 10 || !bVar3) && y.605 < 10 == bVar3) {
                  iVar2 = 0x630c9814;
                }
              }
              else if ((iVar4 == 0x30eb2ad3) && (iVar2 = -0x19738086, local_74 < 1)) {
                iVar2 = 0x1448f36a;
              }
            }
            else {
              iVar2 = 0x10c582e1;
              if (iVar4 != 0x3adaec18) {
                if (iVar4 == 0x4ef970d9) {
                  local_70 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_00140270);
                  uVar1 = (x.604 + -1) * x.604;
                  bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
                  iVar2 = -0x85b1ede;
                  if (9 < y.605 == bVar3 && (9 < y.605 || bVar3)) {
                    iVar2 = 0x630c9814;
                  }
                }
                else {
                  iVar2 = iVar4;
                  if (iVar4 == 0x630c9814) {
                    (**(code **)(*param_1 + 0x538))(param_1,&DAT_00140270);
                    iVar2 = 0x4ef970d9;
                  }
                }
              }
            }
          }
          if (iVar4 < -0x85b1ede) break;
          if (iVar4 == -0x85b1ede) {
            unaff_x21 = local_70;
            iVar2 = -0x232ecf2e;
          }
          else if ((iVar4 == 0x10c582e1) &&
                  (uVar1 = (x.604 + -1) * x.604, bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0,
                  iVar2 = -0x3d7cd38c, 9 < y.605 == bVar3 && (9 < y.605 || bVar3))) {
            iVar2 = 0x3adaec18;
          }
        }
        if (iVar4 != -0x232ecf2e) break;
        uVar1 = (x.604 + -1) * x.604 & 1;
        iVar2 = 0x10c582e1;
        local_68 = unaff_x21;
        if (y.605 < 10 == (uVar1 == 0) && (9 < y.605 | uVar1) == 1) {
          iVar2 = 0x3adaec18;
        }
      }
      if (iVar4 != -0x19738086) break;
      unaff_x21 = (**(code **)(*param_1 + 0x538))(param_1,local_80);
      iVar2 = -0x232ecf2e;
    }
  } while (iVar4 != -0x3d7cd38c);
  return local_68;
}

