
rule Trojan_BAT_AgentTesla_NUB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 44 53 53 53 53 53 53 53 53 53 53 53 53 57 } //01 00  FDSSSSSSSSSSSSW
		$a_81_1 = {57 44 43 57 43 46 44 52 52 } //01 00  WDCWCFDRR
		$a_81_2 = {57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 00 } //01 00  块块块块块块块块块W
		$a_81_3 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}