
rule Ransom_Win32_AtomCore_DA_MTB{
	meta:
		description = "Ransom:Win32/AtomCore.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {64 65 63 72 79 70 74 69 6f 6e 5f 70 72 69 63 65 } //01 00 
		$a_81_1 = {62 69 74 63 6f 69 6e 5f 75 73 65 72 5f 61 64 64 72 65 73 73 } //01 00 
		$a_81_2 = {7c 2a 2e 70 64 66 } //01 00 
		$a_81_3 = {74 72 61 63 6b 69 6e 67 5f 69 64 } //01 00 
		$a_81_4 = {61 74 6f 6d 5f 63 6f 72 65 } //00 00 
	condition:
		any of ($a_*)
 
}