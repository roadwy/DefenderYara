
rule Trojan_BAT_AgentTesla_FKEC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FKEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {76 73 64 76 73 64 76 73 64 73 64 76 2e 65 78 65 } //01 00  vsdvsdvsdsdv.exe
		$a_81_1 = {73 64 76 73 64 73 64 76 64 73 } //01 00  sdvsdsdvds
		$a_81_2 = {76 73 64 76 73 64 76 64 73 76 73 64 } //01 00  vsdvsdvdsvsd
		$a_81_3 = {76 73 64 76 73 64 73 76 } //01 00  vsdvsdsv
		$a_81_4 = {52 65 73 6f 6c 76 65 53 69 67 6e 61 74 75 72 65 } //01 00  ResolveSignature
		$a_81_5 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_6 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //00 00  GetExecutingAssembly
	condition:
		any of ($a_*)
 
}