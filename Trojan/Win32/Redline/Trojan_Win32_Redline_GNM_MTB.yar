
rule Trojan_Win32_Redline_GNM_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 72 4f 51 57 4a 52 56 4f 51 57 4f 4a 52 58 5a 4f 4a 51 57 4f } //01 00  xrOQWJRVOQWOJRXZOJQWO
		$a_01_1 = {71 79 78 6b 65 62 66 73 63 6c 68 75 } //01 00  qyxkebfsclhu
		$a_01_2 = {74 78 7a 79 63 72 7a 73 6f 72 6e 6b 79 67 76 67 6b 63 6a 64 66 72 61 70 } //01 00  txzycrzsornkygvgkcjdfrap
		$a_80_3 = {53 6f 6e 6f 72 6f 75 73 6c 79 20 68 6f 73 70 69 74 61 62 6c 65 } //Sonorously hospitable  00 00 
	condition:
		any of ($a_*)
 
}