
rule Ransom_MSIL_CobraLocker_DE_MTB{
	meta:
		description = "Ransom:MSIL/CobraLocker.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 68 6f 49 73 4c 6f 63 6b 69 6e 67 } //01 00 
		$a_81_1 = {41 54 54 45 4e 54 49 4f 4e 21 21 21 2e 74 78 74 } //01 00 
		$a_81_2 = {52 65 62 6f 6f 74 52 65 61 73 6f 6e 4e 6f 6e 65 } //01 00 
		$a_81_3 = {52 75 6e 41 73 44 6c 6c } //01 00 
		$a_81_4 = {2e 6c 6f 63 6b 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}