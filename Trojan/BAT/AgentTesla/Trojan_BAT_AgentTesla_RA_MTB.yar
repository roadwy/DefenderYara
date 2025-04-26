
rule Trojan_BAT_AgentTesla_RA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 03 26 2b 03 0a 2b 00 06 ?? 2d 49 26 06 17 58 ?? 2d 49 26 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}