
rule Ransom_Win32_Enestedel_V_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.V!rsm,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd2 00 ffffffd2 00 05 00 00 64 00 "
		
	strings :
		$a_03_0 = {68 00 00 00 80 90 0a 34 00 6a 50 90 02 18 6a 03 90 02 20 6a 01 90 00 } //64 00 
		$a_03_1 = {6a 40 68 00 30 00 00 90 02 10 68 96 02 00 90 00 } //64 00 
		$a_03_2 = {68 96 02 00 00 90 0a 10 00 68 00 30 00 00 90 0a 18 00 6a 40 90 00 } //0a 00 
		$a_01_3 = {05 00 40 00 46 } //0a 00 
		$a_01_4 = {06 00 40 00 46 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Enestedel_V_rsm_2{
	meta:
		description = "Ransom:Win32/Enestedel.V!rsm,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b c1 99 f7 7d 90 01 01 8b 45 90 01 01 8a 8a 90 01 04 c0 e1 03 88 08 8b 4d 90 01 01 30 08 41 3b ce 89 4d 90 01 01 7c d7 90 00 } //01 00 
		$a_03_1 = {6a 03 6a 00 ff 30 51 68 90 01 04 ff 55 90 01 01 8b f0 6a 00 56 ff 55 90 00 } //01 00 
		$a_03_2 = {6a 04 8b f0 57 c7 06 00 80 00 00 ff 55 90 01 01 6a 04 57 89 45 90 01 01 c7 00 01 00 00 00 ff 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}