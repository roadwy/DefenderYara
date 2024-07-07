
rule Trojan_BAT_Lokibot_PSIY_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.PSIY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 20 c7 01 00 00 20 8d 01 00 00 28 13 00 00 2b 0d 16 13 0a 11 0a 90 01 1d 09 6f 90 01 03 0a d4 8d 24 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f 90 01 03 0a 26 11 0b 20 cd 01 00 00 93 20 24 34 00 00 59 13 0a 2b b3 28 90 01 03 0a 11 04 6f 90 01 03 0a 13 05 de 52 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}