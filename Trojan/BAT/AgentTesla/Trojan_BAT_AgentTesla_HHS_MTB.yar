
rule Trojan_BAT_AgentTesla_HHS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a dd 90 01 04 08 39 90 01 04 08 6f 90 01 03 0a dc 07 6f 90 01 03 0a 0d dd 90 01 04 07 39 90 01 04 07 6f 90 01 03 0a dc 90 00 } //01 00 
		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 2e 53 74 72 61 74 65 67 69 65 73 2e 45 76 65 6e 74 56 69 73 69 74 6f 72 53 74 72 61 74 65 67 79 } //01 00  ClassLibrary1.Strategies.EventVisitorStrategy
		$a_81_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}