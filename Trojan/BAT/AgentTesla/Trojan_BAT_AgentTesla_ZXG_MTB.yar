
rule Trojan_BAT_AgentTesla_ZXG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ZXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 13 0a 11 05 17 58 13 0b 11 05 11 06 5d 13 0c 11 0b 11 06 5d 13 0d 09 11 0d 91 11 0a 58 13 0e 09 11 0c 91 13 0f 11 04 11 05 1f 16 5d 91 13 10 11 0f 11 10 61 13 11 11 11 11 0e 59 13 12 09 11 0c 11 12 11 0a 5d d2 9c 11 05 17 58 13 05 00 11 05 11 06 fe 04 13 13 11 13 2d a0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}