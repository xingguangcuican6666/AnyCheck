
ulong Java_icu_nullptr_nativetest_NTRZygotePreload_check(void)

{
  int *piVar1;
  size_t sVar2;
  long *plVar3;
  byte bVar4;
  __dev_t _Var5;
  __ino_t _Var6;
  bool bVar7;
  int iVar8;
  long lVar9;
  DIR *pDVar10;
  dirent *pdVar11;
  undefined8 *puVar12;
  size_t sVar13;
  int *piVar14;
  undefined8 uVar15;
  ulong uVar16;
  uint uVar17;
  int iVar18;
  byte *pbVar19;
  void *__src;
  undefined8 *puVar20;
  int *piVar21;
  byte *pbVar22;
  long *plVar23;
  size_t __n;
  undefined8 *puVar24;
  long lVar25;
  uint uVar26;
  int *piVar27;
  undefined1 uStack_4a8;
  undefined4 uStack_4a7;
  undefined1 uStack_4a3;
  timespec tStack_490;
  long *plStack_480;
  stat asStack_470 [7];
  int iStack_6c;
  ulong uStack_68;
  
  tStack_490.tv_sec = 0;
  tStack_490.tv_nsec = 0;
  clock_gettime(5,&tStack_490);
  usleep(100);
  asStack_470[0].st_ctim.tv_sec = 0;
  asStack_470[0].st_mtim.tv_nsec = 0;
  asStack_470[0].__unused[0] = 0;
  asStack_470[0].st_ctim.tv_nsec = 0;
  asStack_470[0].st_mtim.tv_sec = 0;
  asStack_470[0].st_atim.tv_nsec = 0;
  asStack_470[0].st_mode = 0;
  asStack_470[0].st_uid = 0;
  asStack_470[0].st_nlink = 0;
  asStack_470[0].st_rdev = 0;
  asStack_470[0].st_gid = 0;
  asStack_470[0].__pad0 = 0;
  asStack_470[0].st_blksize = 0;
  asStack_470[0].st_size = 0;
  asStack_470[0].st_atim.tv_sec = 0;
  asStack_470[0].st_blocks = 0;
  asStack_470[0].st_ino = 0;
  asStack_470[0].st_dev = 0;
  iVar8 = fstatat(-100,"/proc/self/attr/current",asStack_470,0x100);
  if (iVar8 == -1) {
    uVar26 = 0;
  }
  else {
    uVar26 = (uint)((ulong)((asStack_470[0].st_ctim.tv_nsec - tStack_490.tv_nsec) +
                           (asStack_470[0].st_ctim.tv_sec - tStack_490.tv_sec) * 1000000000) >> 0x3f
                   );
  }
  tStack_490.tv_sec = 0;
  tStack_490.tv_nsec = 0;
  plVar23 = (long *)((ulong)&tStack_490 | 1);
  plStack_480 = (long *)0x0;
  lVar9 = syscall(9,&DAT_00105157,"security.selinux",asStack_470,0x3ff);
  if ((int)lVar9 < 0) {
LAB_00166868:
    bVar7 = true;
  }
  else {
    FUN_00164004(&tStack_490,asStack_470);
    uVar16 = (ulong)tStack_490.tv_sec >> 1 & 0x7f;
    if ((tStack_490.tv_sec & 1U) != 0) {
      uVar16 = tStack_490.tv_nsec;
    }
    if (uVar16 != 0x13) goto LAB_00166868;
    plVar3 = plVar23;
    if ((tStack_490.tv_sec & 1U) != 0) {
      plVar3 = plStack_480;
    }
    if ((*plVar3 != 0x7463656a626f3a75 || plVar3[1] != 0x7366706d743a725f) ||
        *(long *)((long)plVar3 + 0xb) != 0x30733a7366706d74) goto LAB_00166868;
    asStack_470[0].st_ctim.tv_sec = 0;
    asStack_470[0].st_mtim.tv_nsec = 0;
    asStack_470[0].__unused[0] = 0;
    asStack_470[0].st_ctim.tv_nsec = 0;
    asStack_470[0].st_mtim.tv_sec = 0;
    asStack_470[0].st_atim.tv_nsec = 0;
    asStack_470[0].st_mode = 0;
    asStack_470[0].st_uid = 0;
    asStack_470[0].st_nlink = 0;
    asStack_470[0].st_rdev = 0;
    asStack_470[0].st_gid = 0;
    asStack_470[0].__pad0 = 0;
    asStack_470[0].st_blksize = 0;
    asStack_470[0].st_size = 0;
    asStack_470[0].st_atim.tv_sec = 0;
    asStack_470[0].st_blocks = 0;
    asStack_470[0].st_ino = 0;
    asStack_470[0].st_dev = 0;
    iVar8 = stat("/mnt",asStack_470);
    if ((iVar8 != 0) || (((uint)asStack_470[0].st_nlink & 0xf000) != 0x4000)) goto LAB_00166868;
    pDVar10 = opendir("/mnt");
    if (pDVar10 != (DIR *)0x0) {
      pdVar11 = readdir(pDVar10);
      if (pdVar11 != (dirent *)0x0) {
        uVar26 = uVar26 | 2;
      }
      closedir(pDVar10);
      goto LAB_00166868;
    }
    bVar7 = false;
  }
  if ((tStack_490.tv_sec & 1U) != 0) {
    (*DAT_001bdcc0)(plStack_480);
  }
  if (bVar7) {
    tStack_490.tv_sec = 0;
    tStack_490.tv_nsec = 0;
    plStack_480 = (long *)0x0;
    lVar9 = syscall(9,"/mnt/obb","security.selinux",asStack_470,0x3ff);
    if ((int)lVar9 < 0) {
LAB_00166998:
      bVar7 = true;
    }
    else {
      FUN_00164004(&tStack_490,asStack_470);
      uVar16 = (ulong)tStack_490.tv_sec >> 1 & 0x7f;
      if ((tStack_490.tv_sec & 1U) != 0) {
        uVar16 = tStack_490.tv_nsec;
      }
      if (uVar16 != 0x13) goto LAB_00166998;
      plVar3 = plVar23;
      if ((tStack_490.tv_sec & 1U) != 0) {
        plVar3 = plStack_480;
      }
      if ((*plVar3 != 0x7463656a626f3a75 || plVar3[1] != 0x7366706d743a725f) ||
          *(long *)((long)plVar3 + 0xb) != 0x30733a7366706d74) goto LAB_00166998;
      asStack_470[0].st_ctim.tv_sec = 0;
      asStack_470[0].st_mtim.tv_nsec = 0;
      asStack_470[0].__unused[0] = 0;
      asStack_470[0].st_ctim.tv_nsec = 0;
      asStack_470[0].st_mtim.tv_sec = 0;
      asStack_470[0].st_atim.tv_nsec = 0;
      asStack_470[0].st_mode = 0;
      asStack_470[0].st_uid = 0;
      asStack_470[0].st_nlink = 0;
      asStack_470[0].st_rdev = 0;
      asStack_470[0].st_gid = 0;
      asStack_470[0].__pad0 = 0;
      asStack_470[0].st_blksize = 0;
      asStack_470[0].st_size = 0;
      asStack_470[0].st_atim.tv_sec = 0;
      asStack_470[0].st_blocks = 0;
      asStack_470[0].st_ino = 0;
      asStack_470[0].st_dev = 0;
      iVar8 = stat("/mnt/obb",asStack_470);
      if ((iVar8 != 0) || (((uint)asStack_470[0].st_nlink & 0xf000) != 0x4000)) goto LAB_00166998;
      pDVar10 = opendir("/mnt/obb");
      if (pDVar10 != (DIR *)0x0) {
        pdVar11 = readdir(pDVar10);
        if (pdVar11 != (dirent *)0x0) {
          uVar26 = uVar26 | 2;
        }
        closedir(pDVar10);
        goto LAB_00166998;
      }
      bVar7 = false;
    }
    if ((tStack_490.tv_sec & 1U) != 0) {
      (*DAT_001bdcc0)(plStack_480);
    }
    if (bVar7) {
      tStack_490.tv_sec = 0;
      tStack_490.tv_nsec = 0;
      plStack_480 = (long *)0x0;
      lVar9 = syscall(9,"/mnt/asec","security.selinux",asStack_470,0x3ff);
      if (-1 < (int)lVar9) {
        FUN_00164004(&tStack_490,asStack_470);
        uVar16 = (ulong)tStack_490.tv_sec >> 1 & 0x7f;
        if ((tStack_490.tv_sec & 1U) != 0) {
          uVar16 = tStack_490.tv_nsec;
        }
        if (uVar16 == 0x13) {
          if ((tStack_490.tv_sec & 1U) != 0) {
            plVar23 = plStack_480;
          }
          if ((*plVar23 == 0x7463656a626f3a75 && plVar23[1] == 0x7366706d743a725f) &&
              *(long *)((long)plVar23 + 0xb) == 0x30733a7366706d74) {
            asStack_470[0].st_ctim.tv_sec = 0;
            asStack_470[0].st_mtim.tv_nsec = 0;
            asStack_470[0].__unused[0] = 0;
            asStack_470[0].st_ctim.tv_nsec = 0;
            asStack_470[0].st_mtim.tv_sec = 0;
            asStack_470[0].st_atim.tv_nsec = 0;
            asStack_470[0].st_mode = 0;
            asStack_470[0].st_uid = 0;
            asStack_470[0].st_nlink = 0;
            asStack_470[0].st_rdev = 0;
            asStack_470[0].st_gid = 0;
            asStack_470[0].__pad0 = 0;
            asStack_470[0].st_blksize = 0;
            asStack_470[0].st_size = 0;
            asStack_470[0].st_atim.tv_sec = 0;
            asStack_470[0].st_blocks = 0;
            asStack_470[0].st_ino = 0;
            asStack_470[0].st_dev = 0;
            iVar8 = stat("/mnt/asec",asStack_470);
            if (((iVar8 == 0) && (((uint)asStack_470[0].st_nlink & 0xf000) == 0x4000)) &&
               (pDVar10 = opendir("/mnt/asec"), pDVar10 != (DIR *)0x0)) {
              pdVar11 = readdir(pDVar10);
              if (pdVar11 != (dirent *)0x0) {
                uVar26 = uVar26 | 2;
              }
              closedir(pDVar10);
            }
          }
        }
      }
      if ((tStack_490.tv_sec & 1U) != 0) {
        (*DAT_001bdcc0)(plStack_480);
      }
    }
  }
  iVar8 = pipe((int *)&tStack_490);
  if (iVar8 == -1) {
    puVar12 = DAT_001bdeb8;
    if (DAT_001bdeb8 == (undefined8 *)0x0) {
LAB_00166c00:
      puVar20 = &DAT_001bdeb8;
      puVar24 = puVar20;
    }
    else {
      do {
        while (puVar20 = puVar12, *(int *)((long)puVar20 + 0x1c) < 0xea) {
          if (*(int *)((long)puVar20 + 0x1c) == 0xe9) goto LAB_00166c98;
          puVar12 = (undefined8 *)puVar20[1];
          if ((undefined8 *)puVar20[1] == (undefined8 *)0x0) goto LAB_00166c38;
        }
        puVar12 = (undefined8 *)*puVar20;
        puVar24 = puVar20;
      } while ((undefined8 *)*puVar20 != (undefined8 *)0x0);
    }
    goto LAB_00166c3c;
  }
  __n = 0xffa13e300;
  lVar9 = syscall(0xdc,0x11,0);
  uStack_68 = 0xffa13e300;
  iVar8 = (int)lVar9;
  if (iVar8 < 0) {
    puVar12 = DAT_001bdeb8;
    if (DAT_001bdeb8 == (undefined8 *)0x0) goto LAB_00166c00;
    do {
      while (puVar20 = puVar12, *(int *)((long)puVar20 + 0x1c) < 0xea) {
        if (*(int *)((long)puVar20 + 0x1c) == 0xe9) goto LAB_00166c98;
        puVar12 = (undefined8 *)puVar20[1];
        if ((undefined8 *)puVar20[1] == (undefined8 *)0x0) goto LAB_00166c38;
      }
      puVar12 = (undefined8 *)*puVar20;
      puVar24 = puVar20;
    } while ((undefined8 *)*puVar20 != (undefined8 *)0x0);
    goto LAB_00166c3c;
  }
  if (iVar8 == 0) goto LAB_0016715c;
  close(tStack_490.tv_sec._4_4_);
  read((int)tStack_490.tv_sec,&uStack_68,8);
  close((int)tStack_490.tv_sec);
  __src = (void *)(uStack_68 ^ 0xffa13e300);
  waitpid(iVar8,&iStack_6c,0);
  lVar9 = 0;
  asStack_470[0].st_dev = 0;
  asStack_470[0].st_ino = 0;
  asStack_470[0].st_nlink = 0;
  do {
    uVar17 = (uint)*(byte *)((long)__src + lVar9);
    if (0x5e < uVar17 - 0x20) {
      uVar17 = 0x20;
    }
    FUN_00167368(asStack_470,uVar17);
    lVar9 = lVar9 + 1;
  } while (lVar9 != 0x400);
  memcpy(&DAT_001bdfa8,__src,0x400);
  if ((asStack_470[0].st_dev & 1) != 0) {
    (*DAT_001bdcc0)(asStack_470[0].st_nlink);
  }
LAB_00166c98:
  sVar13 = strlen((char *)&DAT_001bdfa8);
  __n = strlen((char *)((long)&DAT_001bdfa8 + sVar13 + 1));
  uStack_4a8 = 8;
  uStack_4a7 = 0x666c6573;
  uStack_4a3 = 0;
  FUN_00168c60(asStack_470,&uStack_4a8);
  _Var6 = asStack_470[0].st_ino;
  _Var5 = asStack_470[0].st_dev;
  uVar16 = asStack_470[0].st_ino - asStack_470[0].st_dev;
  if (uVar16 == 0) {
    uVar17 = 0;
    if ((byte *)asStack_470[0].st_dev == (byte *)0x0) goto LAB_00167110;
  }
  else {
    if (0x1745d1745d1745d < (ulong)(((long)uVar16 >> 4) * 0x2e8ba2e8ba2e8ba3)) {
      FUN_001534cc();
LAB_0016715c:
      close((int)tStack_490.tv_sec);
      uVar15 = (*DAT_001bdd88)("/proc/self/mounts",&DAT_00105f5d);
      lVar9 = (*DAT_001bdd78)();
      if (lVar9 != 0) {
        uStack_68 = lVar9 + 0x28U ^ __n;
      }
      (*DAT_001bdd80)(uVar15);
      write(tStack_490.tv_sec._4_4_,&uStack_68,8);
      close(tStack_490.tv_sec._4_4_);
      _Exit(0);
      uVar16 = FUN_0014779c();
      return uVar16;
    }
    if (uVar16 < 2) {
      uVar16 = 1;
    }
    piVar14 = (int *)(*DAT_001bdcb8)(uVar16);
    lVar9 = 0;
    do {
      lVar25 = lVar9 + 0xb0;
      FUN_001559e4((long)piVar14 + lVar9,(byte *)(_Var5 + lVar9));
      lVar9 = lVar25;
    } while ((byte *)(_Var5 + lVar25) != (byte *)_Var6);
    uVar17 = 0;
    piVar27 = (int *)((long)piVar14 + lVar25) + -0x2c;
    piVar21 = piVar14;
    do {
      bVar4 = *(byte *)(piVar21 + 10);
      sVar2 = (ulong)(bVar4 >> 1);
      if ((bVar4 & 1) != 0) {
        sVar2 = *(size_t *)(piVar21 + 0xc);
      }
      if (sVar2 == 0x15) {
        plVar23 = *(long **)(piVar21 + 0xe);
        plVar3 = (long *)((long)piVar21 + 0x29);
        if ((bVar4 & 1) != 0) {
          plVar3 = plVar23;
        }
        if (((piVar21 == piVar27) ||
            ((*plVar3 != 0x6f632f786570612f || plVar3[1] != 0x696f72646e612e6d) ||
             *(long *)((long)plVar3 + 0xd) != 0x7472612e64696f72)) ||
           ((uint)piVar21[0x2c] <= *piVar21 + 1U)) goto LAB_00166e28;
        uVar17 = uVar17 | 4;
      }
      else {
        plVar23 = *(long **)(piVar21 + 0xe);
LAB_00166e28:
        plVar3 = (long *)((long)piVar21 + 0x29);
        if ((bVar4 & 1) != 0) {
          plVar3 = plVar23;
        }
        if (((__n == sVar2) &&
            (iVar8 = memcmp((void *)((long)&DAT_001bdfa8 + sVar13 + 1),plVar3,__n),
            piVar21 != piVar27)) && ((iVar8 == 0 && (*piVar21 + 1U < (uint)piVar21[0x2c])))) {
          uVar17 = uVar17 | 8;
        }
        else if ((sVar2 == 0xc) && (*plVar3 == 0x696d5f617461642f && (int)plVar3[1] == 0x726f7272))
        {
          iVar18 = *piVar21;
          iVar8 = 0;
          do {
            lVar9 = 0;
            iVar18 = iVar18 + -1;
            while (piVar1 = (int *)((long)piVar14 + lVar9), *piVar1 != iVar18) {
              lVar9 = lVar9 + 0xb0;
              if (lVar25 == lVar9) goto LAB_00166d74;
            }
            if (piVar1 == (int *)((long)piVar14 + lVar25)) {
LAB_00166d74:
              uVar17 = uVar17 | 0x10;
              break;
            }
            bVar4 = *(byte *)(piVar1 + 10);
            uVar16 = (ulong)(bVar4 >> 1);
            if ((bVar4 & 1) != 0) {
              uVar16 = *(ulong *)(piVar1 + 0xc);
            }
            if (9 < uVar16) {
              plVar23 = (long *)((long)piVar1 + 0x29);
              if ((bVar4 & 1) != 0) {
                plVar23 = *(long **)(piVar1 + 0xe);
              }
              if (*plVar23 == 0x73752f617461642f && (short)plVar23[1] == 0x7265) break;
            }
            iVar8 = iVar8 + 1;
          } while (iVar8 != 10);
        }
      }
      bVar7 = piVar21 != piVar27;
      piVar21 = piVar21 + 0x2c;
    } while (bVar7);
    do {
      if ((*(byte *)((long)piVar14 + lVar25 + -0x18) & 1) == 0) {
        if ((*(byte *)((long)piVar14 + lVar25 + -0x30) & 1) == 0) goto LAB_00166f70;
LAB_00166fb0:
        (*DAT_001bdcc0)(*(undefined8 *)((long)piVar14 + lVar25 + -0x20));
        if ((*(byte *)((long)piVar14 + lVar25 + -0x48) & 1) != 0) goto LAB_00166fcc;
LAB_00166f7c:
        if ((*(byte *)((long)piVar14 + lVar25 + -0x70) & 1) == 0) goto LAB_00166f84;
LAB_00166fe0:
        (*DAT_001bdcc0)(*(undefined8 *)((long)piVar14 + lVar25 + -0x60));
        if ((*(byte *)((long)piVar14 + lVar25 + -0x88) & 1) != 0) goto LAB_00166ffc;
LAB_00166f90:
        bVar4 = *(byte *)((long)piVar14 + lVar25 + -0xa0);
      }
      else {
        (*DAT_001bdcc0)(*(undefined8 *)((long)piVar14 + lVar25 + -8));
        if ((*(byte *)((long)piVar14 + lVar25 + -0x30) & 1) != 0) goto LAB_00166fb0;
LAB_00166f70:
        if ((*(byte *)((long)piVar14 + lVar25 + -0x48) & 1) == 0) goto LAB_00166f7c;
LAB_00166fcc:
        (*DAT_001bdcc0)(*(undefined8 *)((long)piVar14 + lVar25 + -0x38));
        if ((*(byte *)((long)piVar14 + lVar25 + -0x70) & 1) != 0) goto LAB_00166fe0;
LAB_00166f84:
        if ((*(byte *)((long)piVar14 + lVar25 + -0x88) & 1) == 0) goto LAB_00166f90;
LAB_00166ffc:
        (*DAT_001bdcc0)(*(undefined8 *)((long)piVar14 + lVar25 + -0x78));
        bVar4 = *(byte *)((long)piVar14 + lVar25 + -0xa0);
      }
      if ((bVar4 & 1) != 0) {
        (*DAT_001bdcc0)(*(undefined8 *)((long)piVar14 + lVar25 + -0x90));
      }
      lVar25 = lVar25 + -0xb0;
    } while (lVar25 != 0);
    (*DAT_001bdcc0)(piVar14);
    if ((byte *)_Var5 == (byte *)0x0) goto LAB_00167110;
    if (_Var6 != _Var5) {
      pbVar22 = (byte *)(_Var6 + -0xa0);
      do {
        if ((pbVar22[0x88] & 1) == 0) {
          if ((pbVar22[0x70] & 1) == 0) goto LAB_00167064;
LAB_0016709c:
          (*DAT_001bdcc0)(*(undefined8 *)(pbVar22 + 0x80));
          if ((pbVar22[0x58] & 1) != 0) goto LAB_001670b0;
LAB_0016706c:
          if ((pbVar22[0x30] & 1) == 0) goto LAB_00167074;
LAB_001670c4:
          (*DAT_001bdcc0)(*(undefined8 *)(pbVar22 + 0x40));
          if ((pbVar22[0x18] & 1) != 0) goto LAB_001670d8;
LAB_0016707c:
          bVar4 = *pbVar22;
        }
        else {
          (*DAT_001bdcc0)(*(undefined8 *)(pbVar22 + 0x98));
          if ((pbVar22[0x70] & 1) != 0) goto LAB_0016709c;
LAB_00167064:
          if ((pbVar22[0x58] & 1) == 0) goto LAB_0016706c;
LAB_001670b0:
          (*DAT_001bdcc0)(*(undefined8 *)(pbVar22 + 0x68));
          if ((pbVar22[0x30] & 1) != 0) goto LAB_001670c4;
LAB_00167074:
          if ((pbVar22[0x18] & 1) == 0) goto LAB_0016707c;
LAB_001670d8:
          (*DAT_001bdcc0)(*(undefined8 *)(pbVar22 + 0x28));
          bVar4 = *pbVar22;
        }
        if ((bVar4 & 1) != 0) {
          (*DAT_001bdcc0)(*(undefined8 *)(pbVar22 + 0x10));
        }
        pbVar19 = pbVar22 + -0x10;
        pbVar22 = pbVar22 + -0xb0;
      } while (pbVar19 != (byte *)_Var5);
    }
  }
  (*DAT_001bdcc0)(_Var5);
LAB_00167110:
  return (ulong)(uVar17 | uVar26);
LAB_00166c38:
  puVar24 = puVar20 + 1;
LAB_00166c3c:
  puVar12 = (undefined8 *)(*DAT_001bdcb8)(0x20);
  *puVar12 = 0;
  puVar12[1] = 0;
  *(undefined4 *)((long)puVar12 + 0x1c) = 0xe9;
  puVar12[2] = puVar20;
  *puVar24 = puVar12;
  if ((long *)*DAT_001bdeb0 != (long *)0x0) {
    puVar12 = (undefined8 *)*puVar24;
    DAT_001bdeb0 = (long *)*DAT_001bdeb0;
  }
  FUN_00146d48(DAT_001bdeb8,puVar12);
  DAT_001bdec0 = DAT_001bdec0 + 1;
  goto LAB_00166c98;
}

