
rule Trojan_BAT_DarkTortilla_MKV_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 07 0d 16 13 04 2b 1a 08 03 11 04 9a 28 b4 00 00 0a 1f 5d da b4 6f b5 00 00 0a 00 11 04 17 d6 13 04 11 04 09 31 e1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}