
rule TrojanDropper_BAT_Livate_A{
	meta:
		description = "TrojanDropper:BAT/Livate.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 63 00 74 00 69 00 76 00 61 00 74 00 6f 00 72 00 49 00 45 00 2e 00 65 00 78 00 65 00 } //01 00  ActivatorIE.exe
		$a_01_1 = {75 00 69 00 6e 00 66 00 6f 00 2e 00 64 00 61 00 74 00 } //01 00  uinfo.dat
		$a_01_2 = {76 00 69 00 6e 00 66 00 6f 00 2e 00 64 00 61 00 74 00 } //01 00  vinfo.dat
		$a_01_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 4c 00 69 00 76 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  WindowsLiveUpdate.exe
		$a_01_4 = {74 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 2e 00 64 00 61 00 74 00 } //01 00  tcookies.dat
		$a_01_5 = {57 00 69 00 6e 00 4c 00 69 00 76 00 65 00 5f 00 64 00 6c 00 6c 00 5f 00 70 00 61 00 63 00 6b 00 } //01 00  WinLive_dll_pack
		$a_01_6 = {4d 00 54 00 6f 00 6f 00 6c 00 4c 00 69 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //00 00  MToolLite.exe
		$a_01_7 = {00 5d 04 00 } //00 a8 
	condition:
		any of ($a_*)
 
}