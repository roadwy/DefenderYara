
rule Trojan_BAT_Formbook_NYE_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 54 65 66 73 64 64 64 64 64 6d 70 } //01 00  C:\Tefsdddddmp
		$a_81_1 = {43 3a 5c 4e 65 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 77 54 65 6d 70 } //01 00  C:\NeddddddddddddddddddddddwTemp
		$a_81_2 = {6c 70 42 66 64 73 64 68 68 66 73 64 73 64 73 66 66 75 66 66 65 72 } //01 00  lpBfdsdhhfsdsdsffuffer
		$a_81_3 = {66 66 66 66 66 66 66 64 68 73 64 68 73 64 68 73 68 64 66 68 66 73 64 66 66 66 66 66 66 } //01 00  fffffffdhsdhsdhshdfhfsdffffff
		$a_81_4 = {73 73 66 73 66 64 64 73 68 66 61 73 66 66 } //00 00  ssfsfddshfasff
	condition:
		any of ($a_*)
 
}