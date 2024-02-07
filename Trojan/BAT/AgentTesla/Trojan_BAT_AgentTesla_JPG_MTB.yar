
rule Trojan_BAT_AgentTesla_JPG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 03 04 09 6c 07 5a 58 6f 90 01 03 06 58 0c 09 17 58 0d 09 06 90 00 } //01 00 
		$a_81_1 = {00 45 78 70 00 } //01 00 
		$a_81_2 = {4c 6f 67 31 30 } //01 00  Log10
		$a_81_3 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //01 00  ClassLibrary
		$a_81_4 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00  TripleDESCryptoServiceProvider
	condition:
		any of ($a_*)
 
}