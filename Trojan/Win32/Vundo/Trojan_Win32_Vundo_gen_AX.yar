
rule Trojan_Win32_Vundo_gen_AX{
	meta:
		description = "Trojan:Win32/Vundo.gen!AX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 ec b4 00 00 00 8d 44 24 90 01 01 56 6a 64 50 6a 6a 51 ff 15 90 01 04 8b b4 24 90 01 01 00 00 00 8b c6 83 e8 02 0f 84 90 01 04 83 e8 0d 0f 84 90 01 04 2d 02 01 00 00 74 90 01 01 68 90 00 } //01 00 
		$a_03_1 = {83 ec 1c 56 8b 74 24 90 01 01 57 8b 3d 90 01 04 6a 90 01 01 68 90 01 04 6a 90 01 01 56 ff d7 6a 90 01 01 68 90 01 04 6a 90 01 01 56 ff d7 56 e8 90 00 } //01 00 
		$a_03_2 = {53 56 57 6a 59 ff 15 90 01 04 8b 0d 90 01 04 8b 35 90 01 04 2b ce 03 c1 a3 90 01 04 74 90 01 01 8b 15 90 01 04 6a 00 6a 00 6a 02 52 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}