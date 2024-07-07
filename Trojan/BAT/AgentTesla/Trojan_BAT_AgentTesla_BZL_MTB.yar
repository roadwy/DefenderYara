
rule Trojan_BAT_AgentTesla_BZL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c 11 07 03 28 90 01 03 06 17 da 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}