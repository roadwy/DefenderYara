
rule Ransom_Win32_Enestedel_A_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.A!rsm,SIGNATURE_TYPE_PEHSTR_EXT,36 01 36 01 0a 00 00 64 00 "
		
	strings :
		$a_01_0 = {d2 16 03 00 } //64 00 
		$a_01_1 = {62 00 00 00 } //64 00 
		$a_01_2 = {db 52 00 00 } //0a 00 
		$a_03_3 = {00 10 0f be 0d 90 09 05 00 0f be 05 90 00 } //0a 00 
		$a_03_4 = {00 10 0f bf 0d 90 09 05 00 0f bf 05 90 00 } //0a 00 
		$a_03_5 = {01 10 0f be 0d 90 09 05 00 0f be 05 90 00 } //0a 00 
		$a_03_6 = {01 10 0f bf 0d 90 09 05 00 0f bf 05 90 00 } //0a 00 
		$a_03_7 = {00 10 0f be 05 90 09 05 00 0f be 15 90 00 } //05 00 
		$a_03_8 = {05 00 40 00 62 90 09 02 00 80 90 00 } //05 00 
		$a_03_9 = {05 00 40 00 46 90 09 02 00 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}