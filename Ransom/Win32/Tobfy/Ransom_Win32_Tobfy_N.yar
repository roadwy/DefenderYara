
rule Ransom_Win32_Tobfy_N{
	meta:
		description = "Ransom:Win32/Tobfy.N,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 ee 02 00 00 68 e8 03 00 00 8b 85 90 01 04 99 2b c2 d1 f8 2d 77 01 00 00 50 8b 85 90 01 04 99 2b c2 d1 f8 2d f4 01 00 00 90 00 } //01 00 
		$a_01_1 = {03 55 f8 0f be 02 83 f0 01 8b 4d fc 03 4d f8 88 01 eb af } //01 00 
		$a_03_2 = {83 fa 4f 74 0c 0f be 05 90 01 04 83 f8 4b 75 19 e8 90 00 } //01 00 
		$a_01_3 = {4c 2d 30 2d 63 6b 5f 45 52 } //00 00  L-0-ck_ER
	condition:
		any of ($a_*)
 
}