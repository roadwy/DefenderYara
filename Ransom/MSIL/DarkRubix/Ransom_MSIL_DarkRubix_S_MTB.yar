
rule Ransom_MSIL_DarkRubix_S_MTB{
	meta:
		description = "Ransom:MSIL/DarkRubix.S!MTB,SIGNATURE_TYPE_PEHSTR,04 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 43 00 72 00 79 00 70 00 74 00 6f 00 44 00 61 00 72 00 6b 00 52 00 75 00 62 00 69 00 78 00 } //01 00 
		$a_01_1 = {5c 00 64 00 61 00 72 00 6b 00 72 00 75 00 62 00 69 00 78 00 68 00 61 00 63 00 6b 00 69 00 6e 00 67 00 2e 00 6a 00 70 00 67 00 } //01 00 
		$a_01_2 = {5c 00 75 00 6e 00 6c 00 6f 00 63 00 6b 00 46 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_3 = {48 00 69 00 20 00 79 00 6f 00 75 00 72 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 20 00 49 00 44 00 20 00 69 00 73 00 20 00 22 00 } //01 00 
		$a_01_4 = {49 00 66 00 20 00 79 00 6f 00 75 00 20 00 68 00 61 00 64 00 20 00 70 00 72 00 6f 00 62 00 6c 00 65 00 6d 00 20 00 73 00 65 00 6e 00 74 00 20 00 65 00 6d 00 61 00 69 00 6c 00 20 00 74 00 6f 00 20 00 73 00 75 00 64 00 65 00 69 00 6f 00 40 00 67 00 65 00 74 00 6f 00 2e 00 74 00 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}