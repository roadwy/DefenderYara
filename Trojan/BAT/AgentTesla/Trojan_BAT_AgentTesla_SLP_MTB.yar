
rule Trojan_BAT_AgentTesla_SLP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SLP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {02 11 04 1e 6f 78 00 00 0a 13 05 11 05 18 28 ec 00 00 0a 13 06 11 06 28 ed 00 00 0a 13 07 07 11 07 6f ee 00 00 0a 26 11 04 1e d6 13 04 11 04 09 31 ce } //1
		$a_81_1 = {4c 69 73 74 4e 6f 62 69 66 65 78 2e 52 65 73 6f 75 72 63 65 73 } //1 ListNobifex.Resources
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}