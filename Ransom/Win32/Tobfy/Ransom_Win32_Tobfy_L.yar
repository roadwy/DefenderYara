
rule Ransom_Win32_Tobfy_L{
	meta:
		description = "Ransom:Win32/Tobfy.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 f9 2b ce 74 18 8b 4d 08 80 34 02 90 01 01 42 8d 71 01 8a 19 41 84 db 90 00 } //01 00 
		$a_03_1 = {68 ec 09 00 00 ff 75 f4 6a 58 ff 75 08 ff d7 8b 1d 90 01 04 50 ff d3 68 ec 09 00 00 ff 75 fc 89 45 f0 6a 5a ff 75 08 ff d7 90 00 } //01 00 
		$a_03_2 = {68 ee 02 00 00 2d 77 01 00 00 68 e8 03 00 00 50 8b 45 90 01 01 99 2b c2 d1 f8 2d f4 01 00 00 90 00 } //01 00 
		$a_01_3 = {4c 2d 30 2d 63 6b 5f 45 52 } //00 00  L-0-ck_ER
	condition:
		any of ($a_*)
 
}