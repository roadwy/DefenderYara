
rule Trojan_Win32_Remcos_PB_MTB{
	meta:
		description = "Trojan:Win32/Remcos.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 10 30 04 3e 46 3b f2 7c e7 } //05 00 
		$a_02_1 = {8a 44 19 02 8a 4c 19 03 88 85 90 01 04 8a d1 a1 90 01 04 80 e2 f0 c0 e2 02 88 8d 90 01 04 0a 14 18 81 3d 90 01 06 00 00 88 95 90 01 04 0f 84 90 01 03 00 8a d1 80 e2 fc c0 e2 04 0a 54 18 01 a1 90 01 04 88 95 90 00 } //05 00 
		$a_02_2 = {05 c3 9e 26 00 a3 90 01 04 c1 e8 10 25 ff 7f 00 00 c3 90 09 0a 00 69 05 90 01 04 fd 43 03 00 90 00 } //05 00 
		$a_02_3 = {8a 42 02 88 44 24 90 01 01 8a 42 03 8a f8 88 44 24 90 01 01 80 e7 f0 c0 e7 02 0a 3a 81 f9 90 01 02 00 00 0f 84 90 01 04 8a d8 80 e3 fc c0 e3 04 0a 5a 01 83 f9 90 01 01 75 90 00 } //01 00 
		$a_00_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}