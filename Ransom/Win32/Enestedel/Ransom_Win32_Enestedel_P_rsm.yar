
rule Ransom_Win32_Enestedel_P_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.P!rsm,SIGNATURE_TYPE_PEHSTR_EXT,36 01 2c 01 06 00 00 64 00 "
		
	strings :
		$a_01_0 = {10 15 03 00 } //64 00 
		$a_01_1 = {88 13 00 00 } //64 00 
		$a_03_2 = {6a 50 6a 03 90 01 01 6a 01 68 00 00 00 80 68 90 02 02 00 10 ff 90 00 } //0a 00 
		$a_03_3 = {00 10 0f be 0d 90 09 05 00 0f bf 05 90 00 } //0a 00 
		$a_03_4 = {00 10 0f bf 0d 90 09 05 00 0f be 05 90 00 } //0a 00 
		$a_03_5 = {00 10 0f be 05 90 09 05 00 0f be 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}