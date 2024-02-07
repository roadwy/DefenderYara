
rule TrojanDownloader_Win32_Dofoil_CB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 74 65 77 69 6c 20 79 78 79 70 2e 64 6c 6c } //01 00  otewil yxyp.dll
		$a_01_1 = {65 73 6f 78 65 72 2e 64 6c 6c } //01 00  esoxer.dll
		$a_01_2 = {79 70 65 7a 2e 64 6c 6c } //01 00  ypez.dll
		$a_01_3 = {75 67 65 6b 65 63 2e 64 6c 6c } //01 00  ugekec.dll
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}