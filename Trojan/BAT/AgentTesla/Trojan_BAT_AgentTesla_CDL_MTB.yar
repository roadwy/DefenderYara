
rule Trojan_BAT_AgentTesla_CDL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {07 02 09 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 28 90 01 03 0a 6f 90 01 03 0a 26 09 18 d6 0d 09 08 31 90 00 } //01 00 
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_3 = {54 6f 55 49 6e 74 33 32 } //01 00  ToUInt32
		$a_81_4 = {53 75 62 73 74 72 69 6e 67 } //00 00  Substring
	condition:
		any of ($a_*)
 
}