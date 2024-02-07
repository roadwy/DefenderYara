
rule Trojan_BAT_AgentTesla_BZA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {04 94 9e 7e 90 01 03 04 7e 90 01 03 04 7e 90 01 03 04 9e 7e 90 01 03 04 7e 90 01 03 04 7e 90 01 03 04 94 7e 90 01 03 04 7e 90 01 03 04 94 58 20 00 01 00 00 5d 94 80 90 01 03 04 7e 90 01 03 04 7e 90 01 03 04 02 50 7e 90 01 03 04 91 7e 90 01 03 04 61 d2 9c 7e 90 01 03 04 17 58 80 90 01 03 04 7e 90 01 03 04 02 50 8e 69 90 00 } //01 00 
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //00 00  GetExecutingAssembly
	condition:
		any of ($a_*)
 
}