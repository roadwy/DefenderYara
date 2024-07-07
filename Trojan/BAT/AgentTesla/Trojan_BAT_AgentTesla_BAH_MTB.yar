
rule Trojan_BAT_AgentTesla_BAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 9a 13 06 7e 90 01 01 00 00 04 17 8d 90 01 01 00 00 01 25 16 1f 23 9d 6f 90 01 01 00 00 0a 0d 19 8d 90 01 01 00 00 01 25 16 09 16 9a a2 25 17 09 17 9a a2 25 18 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}