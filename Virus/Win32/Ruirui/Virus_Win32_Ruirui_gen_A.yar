
rule Virus_Win32_Ruirui_gen_A{
	meta:
		description = "Virus:Win32/Ruirui.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8b 8d 90 01 02 ff ff 51 ff 90 0a 30 00 b9 90 01 04 81 e9 90 01 04 8b b5 90 01 02 ff ff 90 00 } //01 00 
		$a_03_1 = {e8 00 00 00 00 58 2d 90 01 04 c2 04 00 90 01 02 58 5a 50 66 81 3a 4d 5a 75 11 8b 42 3c 66 81 3c 10 50 45 75 06 b8 01 00 00 00 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}