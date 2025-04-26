
rule Trojan_BAT_Nanobot_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Nanobot.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 07 8e 69 5d 13 08 11 04 08 6f ?? 00 00 0a 5d 13 09 07 11 08 91 13 0a 08 11 09 6f ?? 00 00 0a 13 0b 02 07 11 04 28 ?? 00 00 06 13 0c 02 17 11 0a 11 0b 11 0c 28 ?? 00 00 06 13 0d 07 11 08 02 11 0d 28 ?? 00 00 06 9c 00 11 04 17 59 13 04 11 04 16 fe 04 16 fe 01 13 0e 11 0e 2d a1 } //5
		$a_01_1 = {03 20 00 01 00 00 5d d2 0a 2b 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}