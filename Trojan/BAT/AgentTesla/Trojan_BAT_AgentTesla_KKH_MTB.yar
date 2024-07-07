
rule Trojan_BAT_AgentTesla_KKH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {25 16 07 7b 0a 00 00 04 a2 6f 90 01 04 26 90 09 29 00 0b 28 90 01 13 16 9a 72 90 01 09 14 14 17 8d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}