
rule Trojan_BAT_AgentTesla_GZZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 6f 90 01 03 0a 13 05 00 07 17 1f 15 6f 90 01 03 0a 13 06 11 05 11 06 59 20 00 00 01 00 58 20 00 00 01 00 5d d1 13 07 08 11 07 6f 90 01 03 0a 26 00 11 04 17 58 13 04 11 04 09 6f 90 01 03 0a 32 bc 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}