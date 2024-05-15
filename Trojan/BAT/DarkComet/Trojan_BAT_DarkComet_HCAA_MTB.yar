
rule Trojan_BAT_DarkComet_HCAA_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.HCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 11 05 07 11 05 91 08 11 05 91 61 28 90 01 01 00 00 0a 25 26 9c 11 05 17 58 13 05 11 05 11 09 31 e0 90 00 } //05 00 
		$a_03_1 = {07 11 04 02 11 04 91 07 8e b7 03 8e b7 5d 59 03 08 91 59 09 58 28 90 01 01 00 00 0a 25 26 9c 08 17 58 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}