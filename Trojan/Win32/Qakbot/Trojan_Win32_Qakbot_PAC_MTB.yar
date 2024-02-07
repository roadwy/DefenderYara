
rule Trojan_Win32_Qakbot_PAC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 55 49 44 5f 50 52 4f 43 45 53 53 4f 52 5f 49 44 4c 45 5f 44 49 53 41 42 4c 45 } //01 00  IUID_PROCESSOR_IDLE_DISABLE
		$a_01_1 = {49 55 49 44 5f 44 49 53 4b 5f 42 55 52 53 54 5f 49 47 4e 4f 52 45 5f 54 48 52 45 53 48 4f 4c 44 } //01 00  IUID_DISK_BURST_IGNORE_THRESHOLD
		$a_01_2 = {49 55 49 44 5f 50 52 4f 43 45 53 53 4f 52 5f 50 41 52 4b 49 4e 47 5f 48 45 41 44 52 4f 4f 4d 5f 54 48 52 45 53 48 4f 4c 44 } //01 00  IUID_PROCESSOR_PARKING_HEADROOM_THRESHOLD
		$a_01_3 = {49 49 44 5f 49 42 69 6e 64 53 74 61 74 75 73 43 61 6c 6c 62 61 63 6b 45 78 } //01 00  IID_IBindStatusCallbackEx
		$a_01_4 = {49 46 58 56 69 64 65 6f 55 53 45 52 5f 55 6e 4c 6f 61 64 } //01 00  IFXVideoUSER_UnLoad
		$a_01_5 = {49 5a 4e 33 4d 46 58 31 31 44 58 56 41 32 44 65 76 69 63 65 43 32 45 76 } //01 00  IZN3MFX11DXVA2DeviceC2Ev
		$a_01_6 = {4d 6f 74 64 } //01 00  Motd
		$a_01_7 = {49 5a 54 56 4e 33 4d 46 58 39 4d 46 58 56 65 63 74 6f 72 49 50 31 35 4d 46 58 5f 44 49 53 50 5f 48 41 4e 44 4c 45 45 45 } //00 00  IZTVN3MFX9MFXVectorIP15MFX_DISP_HANDLEEE
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_PAC_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 13 00 00 02 00 "
		
	strings :
		$a_00_0 = {85 c4 e4 fe 81 d1 fc 04 00 00 81 ea 0d 13 00 00 69 ed 96 23 00 00 13 e8 e4 e5 03 f5 ff d7 cd 87 42 87 d4 81 d2 9b 06 00 00 4f 0b d7 50 0f a4 fb } //01 00 
		$a_81_1 = {61 4d 68 5a 69 30 41 56 79 65 2e 64 6c 6c } //01 00  aMhZi0AVye.dll
		$a_81_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_3 = {45 6f 66 59 6b 75 79 } //01 00  EofYkuy
		$a_81_4 = {4a 6c 4d 79 63 71 43 } //01 00  JlMycqC
		$a_81_5 = {4d 63 68 74 75 4c } //01 00  MchtuL
		$a_81_6 = {50 65 69 64 48 67 6a 57 69 } //01 00  PeidHgjWi
		$a_81_7 = {55 79 4b 58 52 54 54 4d 65 53 } //01 00  UyKXRTTMeS
		$a_81_8 = {57 55 52 58 47 61 76 } //01 00  WURXGav
		$a_81_9 = {58 67 54 64 44 5a 6f 71 } //01 00  XgTdDZoq
		$a_81_10 = {59 62 76 78 62 44 50 } //01 00  YbvxbDP
		$a_81_11 = {63 65 6b 73 6a 55 59 5a } //01 00  ceksjUYZ
		$a_81_12 = {63 69 64 54 77 63 79 72 } //01 00  cidTwcyr
		$a_81_13 = {66 47 46 4f 44 5a 7a 48 50 } //01 00  fGFODZzHP
		$a_81_14 = {69 50 55 65 42 76 64 69 } //01 00  iPUeBvdi
		$a_81_15 = {69 55 67 62 69 6f 43 45 } //01 00  iUgbioCE
		$a_81_16 = {6a 41 47 45 4f } //01 00  jAGEO
		$a_81_17 = {71 61 6b 76 72 } //01 00  qakvr
		$a_81_18 = {78 56 6a 72 41 77 53 73 } //00 00  xVjrAwSs
	condition:
		any of ($a_*)
 
}