
rule Ransom_Win32_HiddenTear_A_{
	meta:
		description = "Ransom:Win32/HiddenTear.A!!HiddenTear.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {68 69 64 64 65 6e 5f 74 65 61 72 } //hidden_tear  01 00 
		$a_80_1 = {48 69 64 64 65 6e 54 65 61 72 } //HiddenTear  01 00 
		$a_80_2 = {68 69 64 64 65 6e 2d 74 65 61 72 } //hidden-tear  05 00 
	condition:
		any of ($a_*)
 
}