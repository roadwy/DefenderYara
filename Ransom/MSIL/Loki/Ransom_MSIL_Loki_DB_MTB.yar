
rule Ransom_MSIL_Loki_DB_MTB{
	meta:
		description = "Ransom:MSIL/Loki.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {4c 6f 6b 69 20 6c 6f 63 6b 65 72 } //01 00 
		$a_81_1 = {6c 6f 6b 69 5f 5f 5f 43 6f 70 79 } //01 00 
		$a_81_2 = {44 6f 20 6e 6f 74 20 72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //01 00 
		$a_81_3 = {48 6f 77 20 74 6f 20 6f 62 74 61 69 6e 20 42 69 74 63 6f 69 6e 73 } //00 00 
	condition:
		any of ($a_*)
 
}