
rule Trojan_BAT_AgentTesla_PSZN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 7b 85 00 00 04 7e 63 00 00 04 02 9a 7b 5a 00 00 04 9a 7c 31 00 00 04 fe 16 0d 00 00 02 6f 5f 00 00 0a a2 28 ?? 00 00 06 28 ?? 00 00 06 00 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}