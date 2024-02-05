
rule Trojan_BAT_Lokibot_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 11 04 5d 13 06 06 11 07 5d 13 0b 07 11 06 91 13 0c 11 05 11 0b 6f 90 01 01 00 00 0a 13 0d 07 06 17 58 11 04 5d 91 13 0e 11 0c 11 0d 11 0e 28 90 01 01 00 00 06 13 0f 07 11 06 11 0f 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 10 11 10 2d ae 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}