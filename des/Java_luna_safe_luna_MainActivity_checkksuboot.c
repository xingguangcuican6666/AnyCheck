
void Java_luna_safe_luna_MainActivity_checkksuboot(void)

{
  bool bVar1;
  uint uVar2;
  bool bVar3;
  bool bVar4;
  int iVar5;
  
  bVar3 = (~((x.610 + -0x19307b39) * x.610) | 0xfffffffeU) != 0xffffffff;
  bVar1 = 9 < y.611;
  iVar5 = -0x75c20314;
  do {
    while( true ) {
      while (iVar5 < 0x23c1e6a7) {
        if (iVar5 == -0x75c20314) {
          iVar5 = 0x23c1e6a7;
          if (bVar3 == bVar1 && (bVar3 || bVar1)) {
            iVar5 = 0x6c39285;
          }
        }
        else if (iVar5 == 0x6c39285) {
          __system_property_set(&DAT_00140540,&DAT_00140550);
          __android_log_print(3,&DAT_001401c8,&DAT_00140560);
          iVar5 = 0x23c1e6a7;
        }
      }
      if (iVar5 != 0x23c1e6a7) break;
      __system_property_set(&DAT_00140540,&DAT_00140550);
      __android_log_print(3,&DAT_001401c8,&DAT_00140560);
      uVar2 = (x.610 + -1) * x.610;
      bVar4 = ((uVar2 ^ 0xfffffffe) & uVar2) == 0;
      iVar5 = 0x4a0e6114;
      if ((y.611 >= 10 || !bVar4) && y.611 < 10 == bVar4) {
        iVar5 = 0x6c39285;
      }
    }
  } while (iVar5 != 0x4a0e6114);
  return;
}

