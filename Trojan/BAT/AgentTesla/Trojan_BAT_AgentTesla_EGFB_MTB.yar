
rule Trojan_BAT_AgentTesla_EGFB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EGFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0c 1f 0a 58 13 0c 11 09 11 1e 1f 1f 5a 58 13 09 11 0a 11 1e 61 13 0a 11 1e 1f 32 5d 2d 1e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}