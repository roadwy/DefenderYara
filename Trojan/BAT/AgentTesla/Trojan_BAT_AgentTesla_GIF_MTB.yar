
rule Trojan_BAT_AgentTesla_GIF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 16 13 04 2b 31 16 13 04 2b 1e 07 09 11 04 6f 90 01 03 0a 13 06 08 12 06 28 90 01 03 0a 6f 90 01 03 0a 11 04 17 58 13 04 11 04 07 6f 90 01 03 0a 32 d8 09 17 58 0d 09 07 6f 90 01 03 0a 32 c6 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}