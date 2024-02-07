
rule PWS_Win32_Lmir_gen_K{
	meta:
		description = "PWS:Win32/Lmir.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8a 0c ffffff80 0c 55 00 00 ffffffe8 03 "
		
	strings :
		$a_00_0 = {48 6f 6f 6b 50 72 6f 63 } //e8 03  HookProc
		$a_00_1 = {49 6e 73 74 61 6c 6c 41 4c 4c 48 6f 6f 6b } //e8 03  InstallALLHook
		$a_00_2 = {54 72 6f 79 44 4c 4c 2e 64 6c 6c } //32 00  TroyDLL.dll
		$a_00_3 = {57 53 41 53 74 61 72 74 75 70 } //32 00  WSAStartup
		$a_01_4 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //32 00  ReadProcessMemory
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //32 00  WriteProcessMemory
		$a_01_6 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //05 00  Toolhelp32ReadProcessMemory
		$a_00_7 = {6d 69 72 2e 64 61 74 } //01 00  mir.dat
		$a_00_8 = {77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //01 00  www.microsoft.com
		$a_00_9 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00  explorer.exe
		$a_00_10 = {41 63 74 69 76 65 4e 65 74 77 6f 72 6b 4d 6f 6e 69 74 6f 72 2e 65 78 65 } //01 00  ActiveNetworkMonitor.exe
		$a_00_11 = {61 64 6e 73 5f 64 6c 6c 2e 64 6c 6c } //01 00  adns_dll.dll
		$a_00_12 = {62 76 74 76 65 72 73 69 6f 6e 2e 64 6c 6c } //01 00  bvtversion.dll
		$a_00_13 = {63 61 69 6e 2e 65 78 65 } //01 00  cain.exe
		$a_00_14 = {43 61 70 32 6b 2e 64 6c 6c } //01 00  Cap2k.dll
		$a_00_15 = {43 61 70 6e 74 2e 64 6c 6c } //01 00  Capnt.dll
		$a_00_16 = {43 61 70 74 75 72 65 4e 65 74 2e 65 78 65 } //01 00  CaptureNet.exe
		$a_00_17 = {63 6d 6d 6f 6e 7a 63 2e 64 6c 6c } //01 00  cmmonzc.dll
		$a_00_18 = {63 70 6f 72 74 73 2e 65 78 65 } //01 00  cports.exe
		$a_00_19 = {63 75 74 65 73 6e 69 66 66 65 72 2e 65 78 65 } //01 00  cutesniffer.exe
		$a_00_20 = {63 76 2e 65 78 65 } //01 00  cv.exe
		$a_00_21 = {65 67 75 69 2e 65 78 65 } //01 00  egui.exe
		$a_00_22 = {65 68 73 6e 69 66 66 65 72 2e 65 78 65 } //01 00  ehsniffer.exe
		$a_00_23 = {65 6e 74 2e 65 78 65 } //01 00  ent.exe
		$a_00_24 = {65 6e 74 75 74 69 6c 2e 64 6c 6c } //01 00  entutil.dll
		$a_00_25 = {65 71 6e 65 74 78 2e 64 6c 6c } //01 00  eqnetx.dll
		$a_00_26 = {45 74 68 65 72 65 61 6c 2e 65 78 65 } //01 00  Ethereal.exe
		$a_00_27 = {65 79 65 2e 65 78 65 } //01 00  eye.exe
		$a_00_28 = {66 73 61 76 2e 65 78 65 } //01 00  fsav.exe
		$a_00_29 = {66 77 63 6f 6d 2e 65 78 65 } //01 00  fwcom.exe
		$a_00_30 = {66 77 6d 61 69 6e 2e 65 78 65 } //01 00  fwmain.exe
		$a_00_31 = {67 61 67 65 6e 74 2e 64 6c 6c } //01 00  gagent.dll
		$a_00_32 = {67 63 65 6e 74 65 72 2e 65 78 65 } //01 00  gcenter.exe
		$a_00_33 = {69 63 65 73 77 6f 72 64 2e 65 78 65 } //01 00  icesword.exe
		$a_00_34 = {69 63 6f 6e 76 2e 64 6c 6c } //01 00  iconv.dll
		$a_00_35 = {69 72 69 73 2e 65 78 65 } //01 00  iris.exe
		$a_00_36 = {6a 61 68 70 61 63 6b 65 74 2e 64 6c 6c } //01 00  jahpacket.dll
		$a_00_37 = {6b 76 66 77 2e 65 78 65 } //01 00  kvfw.exe
		$a_00_38 = {6b 76 73 6f 63 6b 5f 31 2e 64 6c 6c } //01 00  kvsock_1.dll
		$a_00_39 = {4c 47 55 49 53 64 6b 52 65 73 2e 64 6c 6c } //01 00  LGUISdkRes.dll
		$a_00_40 = {6d 74 6e 61 2e 65 78 65 } //01 00  mtna.exe
		$a_00_41 = {6e 65 74 61 63 72 79 70 74 6f 2e 64 6c 6c } //01 00  netacrypto.dll
		$a_00_42 = {4e 65 74 41 6e 61 6c 79 7a 65 72 2e 65 78 65 } //01 00  NetAnalyzer.exe
		$a_00_43 = {6e 65 74 63 68 65 63 6b 2e 65 78 65 } //01 00  netcheck.exe
		$a_00_44 = {4e 65 74 43 6f 6e 6e 65 63 74 4d 61 6e 61 67 65 72 2e 65 78 65 } //01 00  NetConnectManager.exe
		$a_00_45 = {4e 65 74 50 72 79 65 72 2e 65 78 65 } //01 00  NetPryer.exe
		$a_00_46 = {4e 65 74 53 6e 69 66 66 65 72 56 33 2e 65 78 65 } //01 00  NetSnifferV3.exe
		$a_00_47 = {4e 65 74 77 6f 72 6b 56 69 65 77 2e 65 78 65 } //01 00  NetworkView.exe
		$a_00_48 = {4e 45 54 58 52 41 59 2e 45 58 45 } //01 00  NETXRAY.EXE
		$a_00_49 = {50 61 63 53 63 6f 70 65 2e 65 78 65 } //01 00  PacScope.exe
		$a_00_50 = {50 65 65 70 4e 65 74 2e 65 78 65 } //01 00  PeepNet.exe
		$a_00_51 = {70 66 77 2e 65 78 65 } //01 00  pfw.exe
		$a_00_52 = {70 70 69 68 61 70 69 2e 64 6c 6c } //01 00  ppihapi.dll
		$a_00_53 = {72 66 77 64 72 76 2e 64 6c 6c } //01 00  rfwdrv.dll
		$a_00_54 = {72 66 77 6d 61 69 6e 2e 65 78 65 } //01 00  rfwmain.exe
		$a_00_55 = {72 66 77 73 72 76 2e 65 78 65 } //01 00  rfwsrv.exe
		$a_00_56 = {53 65 65 50 6f 72 74 2e 65 78 65 } //01 00  SeePort.exe
		$a_00_57 = {73 66 6d 73 72 76 2e 64 6c 6c } //01 00  sfmsrv.dll
		$a_00_58 = {73 69 66 72 77 6c 73 6e 61 70 69 6e 2e 64 6c 6c } //01 00  sifrwlsnapin.dll
		$a_00_59 = {73 6b 79 6d 69 73 63 2e 64 6c 6c } //01 00  skymisc.dll
		$a_00_60 = {73 6d 62 66 69 6c 65 73 6e 69 66 66 65 72 2e 65 78 65 } //01 00  smbfilesniffer.exe
		$a_00_61 = {73 6d 63 6f 6d 6d 2e 64 6c 6c } //01 00  smcomm.dll
		$a_00_62 = {73 6e 69 66 66 65 6d 2e 65 78 65 } //01 00  sniffem.exe
		$a_00_63 = {73 6e 69 66 66 65 72 2e 65 78 65 } //01 00  sniffer.exe
		$a_00_64 = {73 6e 73 2e 65 78 65 } //01 00  sns.exe
		$a_00_65 = {53 6f 63 6b 4d 6f 6e 35 2e 65 78 65 } //01 00  SockMon5.exe
		$a_00_66 = {73 72 6d 6f 6e 2e 64 6c 6c } //01 00  srmon.dll
		$a_00_67 = {74 63 70 76 69 65 77 2e 65 78 65 } //01 00  tcpview.exe
		$a_00_68 = {74 70 66 77 2e 65 78 65 } //01 00  tpfw.exe
		$a_00_69 = {74 70 77 2e 64 6c 6c } //01 00  tpw.dll
		$a_00_70 = {74 72 6d 61 69 6c 2e 64 6c 6c } //01 00  trmail.dll
		$a_00_71 = {75 73 66 74 5f 65 78 74 2e 64 6c 6c } //01 00  usft_ext.dll
		$a_00_72 = {76 73 6e 69 66 66 65 72 2e 65 78 65 } //01 00  vsniffer.exe
		$a_00_73 = {77 69 74 2e 65 78 65 } //01 00  wit.exe
		$a_00_74 = {77 70 65 20 70 72 6f 2e 65 78 65 } //01 00  wpe pro.exe
		$a_00_75 = {77 70 65 73 70 79 2e 64 6c 6c } //01 00  wpespy.dll
		$a_00_76 = {57 53 6f 63 6b 45 78 70 65 72 74 2e 65 78 65 } //01 00  WSockExpert.exe
		$a_00_77 = {57 53 6f 63 6b 48 6f 6f 6b 2e 64 6c 6c } //01 00  WSockHook.dll
		$a_00_78 = {58 47 75 61 72 64 2e 65 78 65 } //01 00  XGuard.exe
		$a_00_79 = {63 73 72 73 73 2e 65 78 } //01 00  csrss.ex
		$a_00_80 = {73 65 72 76 69 63 65 73 2e 65 78 65 } //01 00  services.exe
		$a_00_81 = {6c 73 61 73 73 2e 65 78 } //01 00  lsass.ex
		$a_00_82 = {61 76 70 63 63 2e 65 78 } //01 00  avpcc.ex
		$a_00_83 = {61 76 70 33 32 2e 65 78 } //01 00  avp32.ex
		$a_00_84 = {61 6e 74 69 76 69 72 75 73 2e 65 78 } //00 00  antivirus.ex
	condition:
		any of ($a_*)
 
}