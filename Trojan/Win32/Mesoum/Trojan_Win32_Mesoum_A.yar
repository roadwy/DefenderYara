
rule Trojan_Win32_Mesoum_A{
	meta:
		description = "Trojan:Win32/Mesoum.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b fd 8a 14 01 32 d3 30 10 88 14 01 40 4f 75 f2 } //01 00 
		$a_03_1 = {8b 4d f0 c7 81 90 01 02 00 00 00 34 12 00 8b 55 f0 c7 82 90 01 02 00 00 00 78 56 00 90 00 } //01 00 
		$a_01_2 = {79 08 49 81 c9 00 ff ff ff 41 8a 4c 0c 10 8a 1c 10 32 d9 88 1c 10 40 3b c6 7c dd } //01 00 
		$a_01_3 = {44 6e 73 4d 6f 6e 69 74 6f 72 5f } //00 00 
	condition:
		any of ($a_*)
 
}