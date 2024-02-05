
rule Ransom_Win32_Enestedel_G_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.G!rsm,SIGNATURE_TYPE_PEHSTR_EXT,fffffff4 01 fffffff4 01 05 00 00 64 00 "
		
	strings :
		$a_03_0 = {6a 01 68 00 00 00 80 68 90 02 02 00 10 ff 90 09 05 00 6a 50 6a 03 90 00 } //64 00 
		$a_03_1 = {05 00 40 00 4d 90 09 02 00 80 90 00 } //64 00 
		$a_03_2 = {05 00 40 00 62 90 09 02 00 80 90 00 } //64 00 
		$a_03_3 = {02 00 40 00 47 90 09 02 00 80 90 00 } //64 00 
		$a_03_4 = {68 00 10 00 00 90 02 05 ff 54 90 02 0c c7 90 02 02 07 00 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}