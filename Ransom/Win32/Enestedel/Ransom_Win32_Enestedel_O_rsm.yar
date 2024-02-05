
rule Ransom_Win32_Enestedel_O_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.O!rsm,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 50 6a 03 6a 00 6a 01 68 00 00 00 80 } //0a 00 
		$a_01_1 = {80 b8 02 00 40 00 47 } //0a 00 
		$a_01_2 = {80 b8 05 00 40 00 4d } //0a 00 
		$a_03_3 = {00 10 0f bf 15 90 09 05 00 0f bf 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Enestedel_O_rsm_2{
	meta:
		description = "Ransom:Win32/Enestedel.O!rsm,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 fa 62 75 09 83 f9 0b 75 04 89 6c 24 90 01 01 0f be b0 02 00 40 00 83 fe 47 75 0e 83 fa 46 75 09 83 f9 0b 75 04 89 6c 24 90 01 01 83 fe 52 75 0d 80 b8 06 00 40 00 46 90 00 } //01 00 
		$a_01_1 = {6a 00 6a 50 6a 03 6a 00 6a 01 68 00 00 00 80 68 } //01 00 
		$a_01_2 = {80 b8 02 00 40 00 47 } //01 00 
		$a_01_3 = {80 b8 05 00 40 00 4d } //00 00 
	condition:
		any of ($a_*)
 
}