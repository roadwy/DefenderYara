
rule Trojan_BAT_AgentTesla_AKK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 1d 5d 16 fe 01 13 05 11 05 2c 12 07 11 04 02 11 04 91 20 d6 00 00 00 61 b4 9c 00 2b 0a 00 07 11 04 02 11 04 91 9c 00 11 04 17 d6 13 04 11 04 09 31 cc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}