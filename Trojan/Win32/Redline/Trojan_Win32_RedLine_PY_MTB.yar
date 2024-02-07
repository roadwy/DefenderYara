
rule Trojan_Win32_RedLine_PY_MTB{
	meta:
		description = "Trojan:Win32/RedLine.PY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 84 24 a8 01 00 00 90 01 04 b8 90 01 04 f7 a4 24 b4 00 00 00 8b 84 24 b4 00 00 00 81 84 24 a4 01 00 00 90 01 04 ff d7 6a 00 ff d3 81 fe 56 53 1c 00 7f 90 01 01 46 81 fe 44 ad cd 13 0f 8c 90 00 } //01 00 
		$a_01_1 = {73 00 65 00 79 00 6f 00 78 00 65 00 64 00 65 00 64 00 75 00 64 00 69 00 62 00 61 00 72 00 75 00 78 00 75 00 66 00 61 00 79 00 75 00 76 00 69 00 } //00 00  seyoxededudibaruxufayuvi
	condition:
		any of ($a_*)
 
}