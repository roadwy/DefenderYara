
rule Trojan_BAT_DarkTortilla_AAQB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 07 07 11 07 28 90 01 01 00 00 0a 03 28 90 01 01 00 00 06 b4 6f 90 01 01 00 00 0a 00 08 17 d6 0c 00 11 06 6f 90 01 01 00 00 0a 13 08 11 08 2d cb 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}