
rule Ransom_Win32_Mehmehowi_A{
	meta:
		description = "Ransom:Win32/Mehmehowi.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 50 ff 90 02 06 ff 90 02 06 eb 90 01 01 50 ff 90 00 } //03 00 
		$a_03_1 = {50 6a 00 6a 01 6a 13 ff 15 90 01 04 8d 45 90 01 01 50 6a 06 6a 00 6a 00 6a 00 68 20 04 00 c0 ff 15 90 00 } //01 00 
		$a_03_2 = {ff ff 6a 10 68 90 01 04 68 90 01 04 6a 00 ff 15 90 00 } //00 00 
		$a_00_3 = {5d 04 00 } //00 88 
	condition:
		any of ($a_*)
 
}