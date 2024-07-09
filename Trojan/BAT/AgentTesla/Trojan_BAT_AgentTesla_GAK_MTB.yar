
rule Trojan_BAT_AgentTesla_GAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 16 0b 16 0a 2b 2d 16 0a 2b 1c 09 07 06 6f ?? 00 00 0a 13 07 11 04 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 06 17 58 0a 06 09 6f ?? 00 00 0a 32 db } //4
		$a_01_1 = {d2 13 35 11 17 1e 63 d1 13 17 11 15 11 0a 91 13 29 11 15 11 0a 11 26 11 29 61 19 11 1f 58 61 11 35 61 d2 9c 11 0a 17 58 13 0a 11 29 13 1f 11 0a 11 23 32 a4 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*4) >=4
 
}