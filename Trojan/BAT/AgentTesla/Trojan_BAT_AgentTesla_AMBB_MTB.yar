
rule Trojan_BAT_AgentTesla_AMBB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0a 12 00 28 ?? 00 00 06 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 28 ?? 00 00 06 28 ?? 00 00 06 2a } //2
		$a_03_1 = {6f 25 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AgentTesla_AMBB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 11 05 11 0a 74 ?? 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 74 ?? 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f ?? 00 00 0a 26 1f 10 13 0e } //1
		$a_01_1 = {21 00 69 03 00 d8 d9 f1 ab ea 8e 16 5f df 71 d2 d5 ed 77 a7 e3 7a 94 5d 00 b5 70 d4 79 c1 05 b0 6b 63 9d 43 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}