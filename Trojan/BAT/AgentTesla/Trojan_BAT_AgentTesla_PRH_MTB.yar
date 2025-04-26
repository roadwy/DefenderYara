
rule Trojan_BAT_AgentTesla_PRH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PRH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 06 17 58 20 ff 00 00 00 5f 13 06 11 05 11 04 11 06 95 58 20 ff 00 00 00 5f 13 05 02 11 04 11 06 8f 78 00 00 01 11 04 11 05 8f 78 00 00 01 28 ?? 00 00 06 00 11 04 11 06 95 11 04 11 05 95 58 20 ff 00 00 00 5f 13 0f 09 11 0e 07 11 0e 91 11 04 11 0f 95 61 d2 9c 00 11 0e 17 58 13 0e 11 0e 09 8e 69 fe 04 13 10 11 10 2d 94 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}