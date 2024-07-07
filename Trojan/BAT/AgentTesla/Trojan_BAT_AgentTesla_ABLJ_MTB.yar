
rule Trojan_BAT_AgentTesla_ABLJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABLJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 08 17 8d 90 01 03 01 25 16 11 04 8c 90 01 03 01 a2 14 28 90 01 03 0a a2 25 17 1f 10 8c 90 01 03 01 a2 6f 90 01 03 0a a2 14 14 14 17 28 90 01 03 0a 26 90 0a 5f 00 09 14 72 90 01 03 70 17 8d 90 01 03 01 25 16 72 90 01 03 70 28 90 01 03 0a 72 90 01 03 70 20 90 01 03 00 14 14 18 8d 90 00 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}