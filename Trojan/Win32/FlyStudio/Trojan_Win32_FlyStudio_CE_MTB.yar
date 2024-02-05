
rule Trojan_Win32_FlyStudio_CE_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 0c 02 03 d0 03 d8 2b e8 3b e8 88 0b 77 f1 } //01 00 
		$a_03_1 = {33 f8 d1 e8 85 c7 75 f8 8b 54 24 18 bd 01 00 00 00 8b cb 33 f8 d3 e5 8b 8c 94 90 01 04 8d 84 94 90 01 04 89 7c 24 38 4d 23 ef 3b e9 74 20 90 00 } //01 00 
		$a_01_2 = {77 77 77 2e 64 79 77 74 2e 63 6f 6d 2e 63 6e } //01 00 
		$a_01_3 = {42 42 74 6f 6f 6c 73 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}