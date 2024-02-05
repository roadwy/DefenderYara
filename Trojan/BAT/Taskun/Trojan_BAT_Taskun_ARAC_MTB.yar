
rule Trojan_BAT_Taskun_ARAC_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 05 08 6f 53 00 00 0a 5d 13 06 11 05 08 6f 53 00 00 0a 5b 13 07 08 72 36 01 00 70 18 18 8d 90 01 03 01 25 16 11 06 8c 90 01 03 01 a2 25 17 11 07 8c 90 01 03 01 a2 28 90 01 03 0a a5 19 00 00 01 13 08 12 08 28 55 00 00 0a 13 09 07 11 09 6f 90 01 03 0a 00 00 11 05 17 58 13 05 11 05 08 6f 53 00 00 0a 08 6f 57 00 00 0a 5a fe 04 13 0a 11 0a 2d 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}