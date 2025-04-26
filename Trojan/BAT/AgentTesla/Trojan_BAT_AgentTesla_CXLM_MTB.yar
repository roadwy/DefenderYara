
rule Trojan_BAT_AgentTesla_CXLM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CXLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 22 11 0d 11 11 11 0d 91 9d 11 0d 17 58 13 0d 11 0d 11 1a 32 ea } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}