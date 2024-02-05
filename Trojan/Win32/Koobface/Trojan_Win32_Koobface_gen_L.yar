
rule Trojan_Win32_Koobface_gen_L{
	meta:
		description = "Trojan:Win32/Koobface.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 04 00 "
		
	strings :
		$a_01_0 = {8d 4d fc 6a 00 51 ff d0 85 c0 74 0a f6 45 fc 07 74 04 b0 01 } //02 00 
		$a_01_1 = {83 c3 0b 8b c7 2b c3 } //01 00 
		$a_01_2 = {66 62 63 68 65 63 6b } //01 00 
		$a_01_3 = {67 63 68 65 63 6b 67 65 6e } //02 00 
		$a_00_4 = {26 63 72 63 3d 25 64 } //01 00 
		$a_00_5 = {25 73 3f 61 25 73 6e 3d 25 73 67 65 6e 26 76 3d 25 73 26 } //00 00 
	condition:
		any of ($a_*)
 
}