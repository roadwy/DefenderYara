
rule Trojan_BAT_AgentTesla_PSZD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 72 a9 01 00 70 28 90 01 01 00 00 06 0a 28 90 01 01 00 00 06 00 06 28 90 01 01 00 00 06 0b 07 14 fe 03 0c 08 2c 71 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}