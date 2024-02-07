
rule VirTool_Win32_Dijecto_B{
	meta:
		description = "VirTool:Win32/Dijecto.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 68 69 2e 64 61 74 00 } //01 00 
		$a_01_1 = {65 72 72 6f 72 20 69 6e 20 61 6c 6f 63 61 74 69 6e 67 20 6d 6d 65 6f 72 79 21 0a 00 } //01 00 
		$a_00_2 = {44 00 69 00 67 00 69 00 74 00 52 00 65 00 63 00 2e 00 2e 00 2e 00 } //01 00  DigitRec...
		$a_00_3 = {8b 4c 24 60 8b 44 24 74 dd 84 24 9c 00 00 00 8b 09 83 c4 50 83 c0 08 ba 04 00 00 00 dd 00 dc 21 83 c0 08 83 c1 08 4a d9 c0 d8 c9 de c2 dd d8 75 eb } //01 00 
		$a_00_4 = {dc 5d 18 df e0 f6 c4 01 75 14 8b 44 24 1c 40 3d 98 3a 00 00 89 44 24 1c 0f 8c 4e fe ff ff 8b 4d 10 8b 54 24 14 } //00 00 
		$a_00_5 = {5d 04 00 } //00 fd 
	condition:
		any of ($a_*)
 
}