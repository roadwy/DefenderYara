
rule Trojan_BAT_DarkTortilla_MBHT_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MBHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 09 91 13 04 09 1d 5d 13 05 07 11 05 9a 13 06 03 09 02 11 06 11 04 28 90 01 01 00 00 06 9c 09 05 fe 01 13 07 11 07 2c 07 28 90 01 01 00 00 0a 0a 00 00 09 17 d6 0d 09 08 31 c9 90 00 } //01 00 
		$a_01_1 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 73 00 00 0d 49 00 6e 00 76 00 6f 00 6b 00 65 00 00 09 4c 00 6f 00 61 00 64 00 00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f } //00 00 
	condition:
		any of ($a_*)
 
}