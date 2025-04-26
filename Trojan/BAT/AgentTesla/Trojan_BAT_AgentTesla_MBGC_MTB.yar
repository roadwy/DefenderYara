
rule Trojan_BAT_AgentTesla_MBGC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 3b 16 0d 2b 29 11 08 06 08 58 07 09 58 6f ?? 00 00 0a 13 10 12 10 28 ?? 00 00 0a 13 0a 11 05 11 04 11 0a 9c 11 04 17 58 13 04 09 17 58 0d 09 17 fe 04 13 0b 11 0b 2d cd } //1
		$a_01_1 = {13 07 16 13 04 20 01 5c 00 00 8d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}