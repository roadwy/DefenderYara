
rule Trojan_Win64_BazarLoader_DE_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {78 6c 6c 2d 74 72 61 6e 73 66 65 72 2e 78 6c 6c } //03 00  xll-transfer.xll
		$a_81_1 = {44 6c 6c 4d 61 69 6e } //03 00  DllMain
		$a_81_2 = {53 65 74 45 78 63 65 6c 31 32 45 6e 74 72 79 50 74 } //03 00  SetExcel12EntryPt
		$a_81_3 = {58 4c 43 61 6c 6c 56 65 72 } //03 00  XLCallVer
		$a_81_4 = {43 6c 61 6e 67 43 6f 6d 70 69 6c 65 5a 2e 64 6c 6c } //03 00  ClangCompileZ.dll
		$a_81_5 = {4d 64 43 61 6c 6c 42 61 63 6b } //00 00  MdCallBack
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BazarLoader_DE_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {78 6c 6c 2d 74 72 61 6e 73 66 65 72 2e 78 6c 6c } //03 00  xll-transfer.xll
		$a_81_1 = {44 6c 6c 4d 61 69 6e } //03 00  DllMain
		$a_81_2 = {53 65 74 45 78 63 65 6c 31 32 45 6e 74 72 79 50 74 } //03 00  SetExcel12EntryPt
		$a_81_3 = {58 4c 43 61 6c 6c 56 65 72 } //03 00  XLCallVer
		$a_81_4 = {4a 61 76 61 4f 62 6a 65 63 74 52 65 66 6c 65 63 74 69 76 65 } //03 00  JavaObjectReflective
		$a_81_5 = {53 61 76 65 20 77 67 65 74 2e 65 78 65 20 74 6f } //00 00  Save wget.exe to
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BazarLoader_DE_MTB_3{
	meta:
		description = "Trojan:Win64/BazarLoader.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {78 6c 6c 2d 74 72 61 6e 73 66 65 72 2e 78 6c 6c } //03 00  xll-transfer.xll
		$a_81_1 = {53 65 74 45 78 63 65 6c 31 32 45 6e 74 72 79 50 74 } //03 00  SetExcel12EntryPt
		$a_81_2 = {4a 65 74 42 72 61 69 6e 73 } //03 00  JetBrains
		$a_81_3 = {42 6f 61 67 45 6c 70 79 44 6a 6d 71 63 78 61 } //03 00  BoagElpyDjmqcxa
		$a_81_4 = {45 69 6b 63 61 54 79 65 6a 6b 6a 55 6a 6c 6e 61 } //03 00  EikcaTyejkjUjlna
		$a_81_5 = {46 70 63 7a 78 6e 61 68 50 69 62 62 71 61 78 66 61 75 65 67 } //00 00  FpczxnahPibbqaxfaueg
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BazarLoader_DE_MTB_4{
	meta:
		description = "Trojan:Win64/BazarLoader.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 } //03 00  CurrentVersion\Policies\Explorer
		$a_81_1 = {52 65 73 74 72 69 63 74 52 75 6e } //03 00  RestrictRun
		$a_81_2 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //03 00  NoNetConnectDisconnect
		$a_81_3 = {4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //03 00  NoRecentDocsHistory
		$a_81_4 = {63 64 77 65 65 77 72 } //03 00  cdweewr
		$a_81_5 = {6a 6b 72 65 65 72 65 } //03 00  jkreere
		$a_81_6 = {47 65 74 4e 61 74 69 76 65 53 79 73 74 65 6d 49 6e 66 6f } //00 00  GetNativeSystemInfo
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BazarLoader_DE_MTB_5{
	meta:
		description = "Trojan:Win64/BazarLoader.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {6c 32 76 39 79 67 6c 6b 6d 69 } //03 00  l2v9yglkmi
		$a_81_1 = {59 4f 55 52 20 44 4f 43 54 4f 52 20 49 53 20 46 49 52 45 44 21 21 21 21 21 21 } //03 00  YOUR DOCTOR IS FIRED!!!!!!
		$a_81_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //03 00  VirtualProtect
		$a_81_3 = {41 63 74 69 76 61 74 65 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //03 00  ActivateKeyboardLayout
		$a_81_4 = {48 74 74 70 41 64 64 52 65 71 75 65 73 74 48 65 61 64 65 72 73 41 } //03 00  HttpAddRequestHeadersA
		$a_81_5 = {46 6f 72 6d 61 74 4d 65 73 73 61 67 65 57 } //03 00  FormatMessageW
		$a_81_6 = {49 6e 74 65 72 6c 6f 63 6b 65 64 50 75 73 68 45 6e 74 72 79 53 4c 69 73 74 } //00 00  InterlockedPushEntrySList
	condition:
		any of ($a_*)
 
}