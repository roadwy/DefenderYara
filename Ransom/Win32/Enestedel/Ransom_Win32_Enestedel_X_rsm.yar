
rule Ransom_Win32_Enestedel_X_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.X!rsm,SIGNATURE_TYPE_PEHSTR_EXT,36 01 36 01 05 00 00 64 00 "
		
	strings :
		$a_03_0 = {3c 00 40 00 8b 90 01 01 80 00 40 00 90 00 } //64 00 
		$a_01_1 = {02 00 40 00 8b } //64 00 
		$a_01_2 = {6a 50 6a 03 } //0a 00 
		$a_03_3 = {6a 50 6a 40 ff 15 90 01 02 00 10 90 00 } //0a 00 
		$a_03_4 = {6a 1e 6a 40 ff 15 90 01 02 00 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}