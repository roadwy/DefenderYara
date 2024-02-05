
rule Ransom_Win32_Enestedel_B_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.B!rsm,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 0b 00 00 1e 00 "
		
	strings :
		$a_01_0 = {6a 50 6a 03 50 6a 01 68 00 00 00 80 52 ff } //0a 00 
		$a_03_1 = {00 10 0f be 0d 90 09 05 00 0f be 05 90 00 } //0a 00 
		$a_03_2 = {00 10 0f bf 0d 90 09 05 00 0f bf 05 90 00 } //0a 00 
		$a_03_3 = {00 10 0f b7 0d 90 09 05 00 0f be 05 90 00 } //0a 00 
		$a_03_4 = {00 10 0f be 05 90 09 05 00 0f be 0d 90 00 } //0a 00 
		$a_03_5 = {00 10 0f be 05 90 09 05 00 0f be 15 90 00 } //0a 00 
		$a_03_6 = {00 10 0f bf 15 90 09 05 00 0f bf 05 90 00 } //0a 00 
		$a_03_7 = {00 10 0f be 05 90 09 05 00 0f bf 15 90 00 } //0a 00 
		$a_03_8 = {00 10 0f be 35 90 09 05 00 0f be 0d 90 00 } //0a 00 
		$a_03_9 = {00 10 0f bf 89 90 09 05 00 0f bf 81 90 00 } //0a 00 
		$a_03_10 = {00 10 0f bf 0d 90 09 05 00 0f be 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}