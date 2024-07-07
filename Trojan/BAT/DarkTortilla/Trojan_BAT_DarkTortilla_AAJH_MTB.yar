
rule Trojan_BAT_DarkTortilla_AAJH_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 07 8c 90 01 01 00 00 01 a2 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 04 1c 13 07 38 90 01 01 ff ff ff 02 18 8d 90 01 01 00 00 01 25 16 07 8c 90 01 01 00 00 01 a2 25 17 11 04 1f 28 61 8c 90 01 01 00 00 01 a2 14 28 90 01 01 00 00 0a 18 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}