
rule Trojan_BAT_DarkTortilla_DOAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.DOAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 02 14 72 90 01 02 00 70 16 8d 90 01 01 00 00 01 14 14 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 18 13 13 2b af 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}