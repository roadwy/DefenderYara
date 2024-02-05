
rule Trojan_Linux_StealthWorker_A_MTB{
	meta:
		description = "Trojan:Linux/StealthWorker.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 6f 72 6b 65 72 53 53 48 5f 62 72 75 74 2e 63 68 65 63 6b 5f 68 6f 6e 65 79 70 6f 74 } //01 00 
		$a_01_1 = {57 6f 72 6b 65 72 53 53 48 5f 62 72 75 74 2e 53 61 76 65 47 6f 6f 64 } //01 00 
		$a_01_2 = {57 6f 72 6b 65 72 48 74 70 61 73 73 77 64 5f 63 68 65 63 6b } //01 00 
		$a_01_3 = {57 6f 72 6b 65 72 57 48 4d 5f 62 72 75 74 } //01 00 
		$a_01_4 = {57 6f 72 6b 65 72 46 54 50 5f 63 68 65 63 6b } //01 00 
		$a_01_5 = {57 6f 72 6b 65 72 48 74 70 61 73 73 77 64 5f 62 72 75 74 } //00 00 
	condition:
		any of ($a_*)
 
}