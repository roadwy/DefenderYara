
rule Trojan_BAT_AgentTesla_BZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0c 02 72 90 01 04 15 16 28 90 01 04 0a 06 13 05 16 13 04 2b 29 11 05 11 04 9a 0d 08 72 90 01 04 09 28 90 01 04 28 90 01 04 28 90 01 04 6f 90 01 04 26 11 04 17 d6 13 04 00 11 04 11 05 8e b7 fe 04 13 06 11 06 2d c9 08 6f 90 01 04 0b 2b 00 07 2a 90 00 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}