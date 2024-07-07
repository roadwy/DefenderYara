
rule Trojan_BAT_DarkTortilla_AAKF_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 07 11 07 28 90 01 01 00 00 0a 03 28 90 01 01 00 00 06 0d 1e 13 0c 2b 9d 07 75 90 01 01 00 00 1b 09 b4 6f 90 01 01 00 00 0a 08 17 d6 0c 1c 13 0c 2b 87 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}