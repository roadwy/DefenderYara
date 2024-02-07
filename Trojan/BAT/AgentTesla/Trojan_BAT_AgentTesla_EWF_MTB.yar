
rule Trojan_BAT_AgentTesla_EWF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 00 24 00 4d 00 4c 00 4b 00 6a 00 63 00 6c 00 6b 00 64 00 73 00 6a 00 66 00 6b 00 6c 00 73 00 64 00 66 00 6b 00 67 00 68 00 66 00 64 00 6b 00 68 00 67 00 66 00 68 00 6d 00 6a 00 6c 00 79 00 69 00 6c 00 24 00 24 00 } //01 00  $$MLKjclkdsjfklsdfkghfdkhgfhmjlyil$$
		$a_01_1 = {41 00 53 00 41 00 4d 00 65 00 74 00 68 00 6f 00 64 00 30 00 41 00 53 00 41 00 } //01 00  ASAMethod0ASA
		$a_01_2 = {24 00 24 00 4e 00 6f 00 42 00 6f 00 64 00 79 00 43 00 61 00 6e 00 47 00 65 00 74 00 49 00 74 00 24 00 24 00 } //01 00  $$NoBodyCanGetIt$$
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_5 = {49 6e 76 6f 6b 65 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}