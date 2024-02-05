
rule Ransom_Win32_Enestedel_U_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.U!rsm,SIGNATURE_TYPE_PEHSTR_EXT,fffffffe 01 fffffffe 01 09 00 00 64 00 "
		
	strings :
		$a_01_0 = {c6 05 00 00 00 00 02 } //64 00 
		$a_03_1 = {05 00 40 00 62 90 09 02 00 80 90 00 } //64 00 
		$a_03_2 = {05 00 40 00 4d 90 09 02 00 80 90 00 } //64 00 
		$a_03_3 = {05 00 40 00 46 90 09 02 00 80 90 00 } //64 00 
		$a_03_4 = {06 00 40 00 46 90 09 02 00 80 90 00 } //0a 00 
		$a_03_5 = {00 10 0f be 1d 90 09 05 00 0f bf 05 90 00 } //0a 00 
		$a_03_6 = {00 10 0f be 3d 90 09 05 00 0f be 1d 90 00 } //0a 00 
		$a_03_7 = {00 10 0f be 35 90 09 05 00 0f bf 05 90 00 } //0a 00 
		$a_03_8 = {00 10 0f be 35 90 09 05 00 0f be 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}