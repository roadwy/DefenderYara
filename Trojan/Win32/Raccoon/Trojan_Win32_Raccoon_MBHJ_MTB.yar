
rule Trojan_Win32_Raccoon_MBHJ_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.MBHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 0d 30 a1 41 02 8a 94 31 4b 13 01 00 8b 0d 90 01 04 88 14 31 3d a8 00 00 00 75 90 01 01 6a 00 ff d7 a1 90 01 04 46 3b f0 72 90 00 } //01 00 
		$a_01_1 = {6c 6f 63 69 79 75 6a 61 76 65 67 69 62 65 79 00 4c 61 63 6f 6b 65 6b 75 20 72 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}