
rule Trojan_BAT_DarkComet_ADB_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 0c 2b 3f 06 08 91 1f 1f fe 02 06 08 91 1f 7f fe 04 5f 2c 14 06 08 13 04 11 04 06 11 04 91 08 1f 1f 5d 17 d6 b4 59 86 9c 06 08 91 1f 20 2f 0f 06 08 13 04 11 04 06 11 04 91 1f 5f 58 86 9c 08 17 d6 0c 08 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}