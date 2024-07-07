
rule Trojan_BAT_Lokibot_CCCD_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.CCCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 07 8e 69 5d 13 07 11 06 08 6f 90 01 04 5d 13 08 07 11 07 91 13 09 08 11 08 6f 90 01 04 13 0a 02 07 11 06 28 90 01 04 13 0b 02 11 09 11 0a 11 0b 28 90 01 04 13 0c 07 11 07 02 11 0c 28 90 01 04 9c 00 11 06 17 59 13 06 11 06 16 fe 04 16 fe 01 13 0d 11 0d 2d a2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}