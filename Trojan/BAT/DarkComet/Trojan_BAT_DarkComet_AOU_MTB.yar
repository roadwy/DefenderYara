
rule Trojan_BAT_DarkComet_AOU_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AOU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {17 6a 59 69 17 58 8d 1b 00 00 01 0b 06 07 16 06 } //01 00 
		$a_01_1 = {54 00 2e 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}