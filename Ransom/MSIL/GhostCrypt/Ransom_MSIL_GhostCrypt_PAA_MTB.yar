
rule Ransom_MSIL_GhostCrypt_PAA_MTB{
	meta:
		description = "Ransom:MSIL/GhostCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //01 00 
		$a_81_1 = {57 61 74 63 68 2d 4d 65 2d 52 65 63 6f 76 65 72 2d 46 69 6c 65 73 } //01 00 
		$a_81_2 = {66 75 63 6b 20 6d 61 6e } //01 00 
		$a_81_3 = {6b 69 6c 6c 6d 65 2e 62 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}