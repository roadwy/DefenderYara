
rule Ransom_Win32_Enestedel_L_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.L!rsm,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 32 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {01 10 0f bf 0d 90 09 05 00 0f bf 15 90 00 } //0a 00 
		$a_03_1 = {01 10 0f be 0d 90 09 05 00 0f be 05 90 00 } //0a 00 
		$a_03_2 = {01 10 0f bf 05 90 09 05 00 0f be 15 90 00 } //0a 00 
		$a_03_3 = {01 10 0f bf 15 90 09 05 00 0f bf 0d 90 00 } //0a 00 
		$a_03_4 = {01 10 0f bf 0d 90 09 05 00 0f bf 05 90 00 } //0a 00 
		$a_03_5 = {02 00 40 00 90 09 02 00 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}