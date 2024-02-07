
rule Trojan_BAT_njRAT_EH_MTB{
	meta:
		description = "Trojan:BAT/njRAT.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 46 43 37 69 4e 38 46 4d } //01 00  GFC7iN8FM
		$a_01_1 = {65 35 33 77 33 34 6d 39 36 38 61 77 43 6d 39 50 38 35 74 61 55 5a 65 } //01 00  e53w34m968awCm9P85taUZe
		$a_01_2 = {65 78 70 6c 6f 72 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  explorer.Resources.resources
		$a_01_3 = {65 78 70 6c 6f 72 65 72 2e 70 64 62 } //01 00  explorer.pdb
		$a_01_4 = {46 00 74 00 43 00 78 00 37 00 42 00 61 00 4c 00 37 00 56 00 45 00 4e 00 52 00 72 00 72 00 53 00 } //00 00  FtCx7BaL7VENRrrS
	condition:
		any of ($a_*)
 
}