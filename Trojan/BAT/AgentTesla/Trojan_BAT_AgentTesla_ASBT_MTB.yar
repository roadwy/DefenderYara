
rule Trojan_BAT_AgentTesla_ASBT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 07 11 06 8e 69 17 da 13 20 16 13 21 38 ?? 00 00 00 11 07 11 06 11 21 9a 1f 10 7e ?? 02 00 04 28 ?? 03 00 06 b4 6f ?? 00 00 0a 00 11 21 17 d6 13 21 11 21 11 20 3e } //4
		$a_81_1 = {43 6f 6c 6c 69 6e 73 53 65 6d 65 73 74 65 72 50 72 6f 6a 65 63 74 2e 52 65 73 6f 75 72 63 65 73 } //1 CollinsSemesterProject.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_81_1  & 1)*1) >=5
 
}