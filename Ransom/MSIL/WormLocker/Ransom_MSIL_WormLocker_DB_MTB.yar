
rule Ransom_MSIL_WormLocker_DB_MTB{
	meta:
		description = "Ransom:MSIL/WormLocker.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {72 61 6e 73 6f 6d 5f 76 6f 69 63 65 2e 76 62 73 } //01 00 
		$a_81_1 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00 
		$a_81_2 = {57 6f 72 6d 4c 6f 63 6b 65 72 } //01 00 
		$a_81_3 = {63 79 62 65 72 77 61 72 65 } //00 00 
	condition:
		any of ($a_*)
 
}