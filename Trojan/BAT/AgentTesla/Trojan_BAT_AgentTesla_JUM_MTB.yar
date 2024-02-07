
rule Trojan_BAT_AgentTesla_JUM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JUM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 25 16 d0 90 01 03 1b 28 90 01 03 0a a2 28 90 01 03 0a 14 17 8d 90 01 03 01 25 16 11 00 28 90 00 } //01 00 
		$a_81_1 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_2 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_4 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_6 = {70 6f 77 65 72 73 68 65 6c 6c } //01 00  powershell
		$a_81_7 = {54 65 73 74 2d 4e 65 74 43 6f 6e 6e 65 63 74 69 6f 6e } //00 00  Test-NetConnection
	condition:
		any of ($a_*)
 
}