
rule Trojan_BAT_DarkTortilla_AAKL_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 1b 13 0c 2b 9d 07 75 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 16 13 0c 2b 87 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}