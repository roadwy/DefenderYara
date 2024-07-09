
rule Trojan_BAT_AgentTesla_RDAP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 07 11 07 47 20 ?? ?? ?? ?? 59 d2 52 11 06 17 58 13 06 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}