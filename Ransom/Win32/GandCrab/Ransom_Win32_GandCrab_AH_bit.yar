
rule Ransom_Win32_GandCrab_AH_bit{
	meta:
		description = "Ransom:Win32/GandCrab.AH!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b ce 8b c6 c1 e9 05 03 4d f8 c1 e0 04 03 45 f4 33 c8 8d 04 33 33 c8 2b f9 8b cf 8b c7 c1 e9 05 03 4d f0 c1 e0 04 } //01 00 
		$a_00_1 = {03 45 ec 33 c8 8d 04 3b 33 c8 8b 45 e8 2b f1 b9 01 00 00 00 2b c8 03 d9 83 6d fc 01 75 ae 8b 45 e4 89 78 04 5f 89 30 5e 5b 8b e5 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}