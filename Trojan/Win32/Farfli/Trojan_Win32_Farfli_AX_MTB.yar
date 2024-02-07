
rule Trojan_Win32_Farfli_AX_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {33 c9 0f b7 d1 8a 54 55 e8 30 14 07 40 41 3b c6 72 e8 } //01 00 
		$a_01_1 = {33 d9 03 d3 8b 5d 10 8b ce 83 e1 03 33 4d f8 8b 1c 8b 0f b6 4c 3e ff 33 d9 03 d8 0f b6 04 3e 33 d3 2b c2 4e 88 44 3e 01 0f b6 c0 75 b5 } //01 00 
		$a_01_2 = {8b 45 08 8a 10 8a 4d ef 32 d1 02 d1 88 10 40 89 45 08 } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}