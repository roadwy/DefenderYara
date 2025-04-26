
rule Trojan_BAT_AgentTesla_AEIS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AEIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 16 16 8c 6a 00 00 01 a2 25 17 08 a2 25 13 05 14 14 18 8d 6b 00 00 01 25 17 17 9c 25 13 06 17 28 } //2
		$a_01_1 = {42 00 6f 00 6f 00 6b 00 6d 00 61 00 6b 00 65 00 72 00 46 00 65 00 65 00 64 00 50 00 61 00 72 00 73 00 65 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 BookmakerFeedParseService
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}