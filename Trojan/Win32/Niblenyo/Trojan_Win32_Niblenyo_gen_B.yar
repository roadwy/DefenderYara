
rule Trojan_Win32_Niblenyo_gen_B{
	meta:
		description = "Trojan:Win32/Niblenyo.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 6f 77 6e 44 4c 4c 2e 64 6c 6c 00 } //01 00 
		$a_03_1 = {8a c3 83 f8 05 90 03 02 06 75 7f 0f 85 84 00 00 00 8b c3 e8 90 01 02 ff ff 84 c0 75 0e 68 90 01 02 40 00 e8 90 01 02 ff ff 8b f0 eb 0c 68 90 01 02 40 00 e8 90 01 02 ff ff 8b f0 6a 02 56 e8 90 00 } //01 00 
		$a_03_2 = {83 7d fc 00 0f 86 90 01 02 00 00 83 3d 90 01 02 40 00 01 1b c0 40 84 c0 0f 85 90 02 0e 8b 45 fc e8 90 01 02 ff ff 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}