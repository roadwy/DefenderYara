
rule Trojan_BAT_AgentTesla_ABNB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 08 17 8d 90 01 03 01 25 16 11 04 8c 90 01 03 01 a2 14 28 90 01 03 0a 28 90 01 03 0a 1f 10 28 90 01 03 0a 86 9c 6f 90 01 03 0a 00 11 04 17 d6 13 04 00 11 04 20 90 01 03 00 fe 04 13 06 11 06 2d b6 90 0a 4a 00 09 17 8d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}