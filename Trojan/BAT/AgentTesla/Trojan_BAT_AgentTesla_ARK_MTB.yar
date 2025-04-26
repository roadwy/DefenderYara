
rule Trojan_BAT_AgentTesla_ARK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ARK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 1f 0d 5a 06 58 1f 11 5d 26 11 04 17 58 13 04 11 04 18 fe 04 13 0f 11 0f 2d e4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}