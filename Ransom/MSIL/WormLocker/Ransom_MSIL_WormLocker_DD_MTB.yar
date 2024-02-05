
rule Ransom_MSIL_WormLocker_DD_MTB{
	meta:
		description = "Ransom:MSIL/WormLocker.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 6f 72 6d 20 4c 6f 63 6b 65 72 2e 65 78 65 } //01 00 
		$a_81_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_81_2 = {43 6f 6e 66 75 73 65 72 45 78 } //01 00 
		$a_81_3 = {44 65 63 6f 6d 70 72 65 73 73 } //01 00 
		$a_81_4 = {44 65 63 72 79 70 74 } //00 00 
	condition:
		any of ($a_*)
 
}