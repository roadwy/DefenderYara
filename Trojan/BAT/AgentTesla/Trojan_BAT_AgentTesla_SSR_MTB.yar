
rule Trojan_BAT_AgentTesla_SSR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 0a 02 11 0a 91 03 11 0a 03 6f 90 01 03 0a 5d 28 90 01 03 06 61 d2 9c 38 90 01 03 00 00 11 0a 17 58 13 0a 20 90 01 03 00 38 21 fe ff ff 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}