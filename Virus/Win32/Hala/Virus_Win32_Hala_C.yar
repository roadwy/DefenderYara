
rule Virus_Win32_Hala_C{
	meta:
		description = "Virus:Win32/Hala.C,SIGNATURE_TYPE_PEHSTR_EXT,5a 00 46 00 47 00 00 03 00 "
		
	strings :
		$a_01_0 = {3f 61 63 74 69 6f 6e 3d 70 6f 73 74 26 48 44 3d 25 73 26 48 4e 3d 25 73 26 4f 54 3d 25 64 26 49 56 3d 25 73 26 4d 4d 3d 25 64 } //02 00  ?action=post&HD=%s&HN=%s&OT=%d&IV=%s&MM=%d
		$a_01_1 = {5f 5f 44 4c 35 58 59 45 58 5f 5f } //03 00  __DL5XYEX__
		$a_01_2 = {5f 5f 44 4c 5f 43 4f 52 45 35 5f 4d 55 54 45 58 5f 5f } //04 00  __DL_CORE5_MUTEX__
		$a_01_3 = {6e 62 74 2d 64 72 61 67 6f 6e 72 61 6a 61 32 30 30 36 2e 65 78 65 } //04 00  nbt-dragonraja2006.exe
		$a_01_4 = {5c 64 33 64 38 78 6f 66 2e 64 6c 6c } //04 00  \d3d8xof.dll
		$a_01_5 = {64 72 61 67 6f 6e 72 61 6a 61 2e 65 78 65 } //04 00  dragonraja.exe
		$a_01_6 = {64 39 64 78 2e 64 6c 6c } //04 00  d9dx.dll
		$a_01_7 = {7a 68 65 6e 67 74 75 2e 65 78 65 } //04 00  zhengtu.exe
		$a_01_8 = {5c 64 39 64 78 2e 64 6c 6c } //04 00  \d9dx.dll
		$a_01_9 = {74 72 6f 6a 61 6e 6b 69 6c 6c 65 72 2e 65 78 65 } //04 00  trojankiller.exe
		$a_01_10 = {6b 61 72 74 72 69 64 65 72 2e 65 78 65 } //01 00  kartrider.exe
		$a_01_11 = {73 65 61 6c 73 70 65 65 64 2e 65 78 65 } //01 00  sealspeed.exe
		$a_01_12 = {78 79 32 2e 65 78 65 } //01 00  xy2.exe
		$a_01_13 = {6e 6d 73 65 72 76 69 63 65 2e 65 78 65 } //01 00  nmservice.exe
		$a_01_14 = {61 73 6b 74 61 6f 2e 65 78 65 } //01 00  asktao.exe
		$a_01_15 = {61 75 64 69 74 69 6f 6e 2e 65 78 65 } //01 00  audition.exe
		$a_01_16 = {70 61 74 63 68 65 72 2e 65 78 65 } //01 00  patcher.exe
		$a_01_17 = {66 6c 79 66 66 2e 65 78 65 } //01 00  flyff.exe
		$a_01_18 = {64 62 66 73 75 70 64 61 74 65 2e 65 78 65 } //01 00  dbfsupdate.exe
		$a_01_19 = {6d 68 63 6c 69 65 6e 74 2d 63 6f 6e 6e 65 63 74 2e 65 78 65 } //01 00  mhclient-connect.exe
		$a_01_20 = {7a 75 6f 6e 6c 69 6e 65 2e 65 78 65 } //01 00  zuonline.exe
		$a_01_21 = {6e 65 75 7a 2e 65 78 65 } //01 00  neuz.exe
		$a_01_22 = {7a 74 63 6f 6e 66 69 67 2e 65 78 65 } //01 00  ztconfig.exe
		$a_01_23 = {6d 61 70 6c 65 73 74 6f 72 79 2e 65 78 65 } //01 00  maplestory.exe
		$a_01_24 = {63 6f 6e 66 69 67 2e 65 78 65 } //01 00  config.exe
		$a_01_25 = {68 73 2e 65 78 65 } //01 00  hs.exe
		$a_01_26 = {6d 6a 6f 6e 6c 69 6e 65 2e 65 78 65 } //01 00  mjonline.exe
		$a_01_27 = {61 75 5f 75 6e 69 6e 73 5f 77 65 62 2e 65 78 65 } //01 00  au_unins_web.exe
		$a_01_28 = {70 61 74 63 68 75 70 64 61 74 65 2e 65 78 65 } //01 00  patchupdate.exe
		$a_01_29 = {63 61 62 61 6c 6d 61 69 6e 39 78 2e 65 78 65 } //01 00  cabalmain9x.exe
		$a_01_30 = {67 63 2e 65 78 65 } //01 00  gc.exe
		$a_01_31 = {6d 61 69 6e 2e 65 78 65 } //01 00  main.exe
		$a_01_32 = {73 66 63 2e 64 6c 6c } //01 00  sfc.dll
		$a_01_33 = {6e 73 73 74 61 72 74 65 72 2e 65 78 65 } //01 00  nsstarter.exe
		$a_01_34 = {77 6f 6f 6f 6c 63 66 67 2e 65 78 65 } //01 00  wooolcfg.exe
		$a_01_35 = {6d 74 73 2e 65 78 65 } //01 00  mts.exe
		$a_01_36 = {75 73 65 72 70 69 63 2e 65 78 65 } //01 00  userpic.exe
		$a_01_37 = {63 61 62 61 6c 2e 65 78 65 } //01 00  cabal.exe
		$a_01_38 = {6e 6d 63 6f 73 72 76 2e 65 78 65 } //01 00  nmcosrv.exe
		$a_01_39 = {78 6c 71 79 32 2e 65 78 65 } //01 00  xlqy2.exe
		$a_01_40 = {77 6f 6f 6f 6c 2e 65 78 65 } //01 00  woool.exe
		$a_01_41 = {6d 65 74 65 6f 72 2e 65 78 65 } //01 00  meteor.exe
		$a_01_42 = {78 79 32 70 6c 61 79 65 72 2e 65 78 65 } //01 00  xy2player.exe
		$a_01_43 = {61 75 74 6f 75 70 64 61 74 65 2e 65 78 65 } //01 00  autoupdate.exe
		$a_01_44 = {53 48 44 4f 43 56 57 2e 44 4c 4c } //01 00  SHDOCVW.DLL
		$a_01_45 = {7a 66 73 2e 65 78 65 } //01 00  zfs.exe
		$a_01_46 = {64 6b 32 2e 65 78 65 } //01 00  dk2.exe
		$a_01_47 = {67 61 6d 65 2e 65 78 65 } //01 00  game.exe
		$a_01_48 = {63 61 62 61 6c 6d 61 69 6e 2e 65 78 65 } //01 00  cabalmain.exe
		$a_01_49 = {63 61 2e 65 78 65 } //01 00  ca.exe
		$a_01_50 = {77 62 2d 73 65 72 76 69 63 65 2e 65 78 65 } //01 00  wb-service.exe
		$a_01_51 = {25 73 2a 2e 2a } //01 00  %s*.*
		$a_01_52 = {3a 5c 57 49 4e 4e 54 5c } //02 00  :\WINNT\
		$a_01_53 = {41 43 50 49 23 50 4e 50 44 4f 44 4f 23 31 23 41 6d 64 5f 44 4c 35 } //01 00  ACPI#PNPDODO#1#Amd_DL5
		$a_01_54 = {64 69 66 66 74 69 6d 65 } //02 00  difftime
		$a_01_55 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 68 65 6c 6c 53 65 72 76 69 63 65 4f 62 6a 65 63 74 44 65 6c 61 79 4c 6f 61 64 } //01 00  Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
		$a_01_56 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //01 00  CreateRemoteThread
		$a_01_57 = {25 64 2e 25 64 } //01 00  %d.%d
		$a_01_58 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  GetThreadContext
		$a_01_59 = {43 68 65 63 6b 42 4b 46 6c 61 67 73 } //02 00  CheckBKFlags
		$a_01_60 = {47 6c 6f 62 61 6c 4d 65 6d 6f 72 79 53 74 61 74 75 73 } //01 00  GlobalMemoryStatus
		$a_01_61 = {57 49 4e 49 4e 45 54 } //01 00  WININET
		$a_01_62 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00  InternetOpenUrlA
		$a_01_63 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //02 00  explorer.exe
		$a_01_64 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //01 00  GetLogicalDrives
		$a_01_65 = {53 66 63 49 73 46 69 6c 65 50 72 6f 74 65 63 74 65 64 } //02 00  SfcIsFileProtected
		$a_01_66 = {4c 4f 43 41 4c 20 53 45 54 54 49 4e 47 53 5c 54 45 4d 50 5c } //02 00  LOCAL SETTINGS\TEMP\
		$a_01_67 = {68 74 6d 6c 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  htmlfile\shell\open\command
		$a_01_68 = {44 69 72 65 63 74 58 20 44 4c 4c } //02 00  DirectX DLL
		$a_01_69 = {53 6f 66 74 77 61 72 65 5c 49 6e 74 65 6c } //02 00  Software\Intel
		$a_01_70 = {53 6f 66 74 77 61 72 65 5c 47 6f 6f 67 6c 65 } //00 00  Software\Google
	condition:
		any of ($a_*)
 
}