
rule Ransom_Win64_ContiCrypt_PM_MTB{
	meta:
		description = "Ransom:Win64/ContiCrypt.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 4f 4e 54 49 5f 52 45 41 44 4d 45 2e 74 78 74 } //01 00 
		$a_81_1 = {2e 43 4f 4e 54 49 } //01 00 
		$a_81_2 = {59 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 4c 4f 43 4b 45 44 2e } //00 00 
	condition:
		any of ($a_*)
 
}