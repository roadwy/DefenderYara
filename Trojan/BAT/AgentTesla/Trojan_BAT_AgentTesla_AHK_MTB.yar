
rule Trojan_BAT_AgentTesla_AHK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0b 6f 03 00 00 0a 13 23 11 0c 11 23 11 10 59 61 13 0c 11 10 11 0c 19 58 1e 63 59 13 10 11 0b 6f 4a 00 00 06 2d d9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}