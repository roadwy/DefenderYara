
rule Trojan_BAT_StormKitty_AAUE_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.AAUE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0c 11 0f 02 11 0f 91 11 07 61 11 0a 11 08 91 61 b4 9c 11 08 03 6f ?? 00 00 0a 17 da 33 05 16 13 08 2b 06 11 08 17 d6 13 08 11 0f 17 d6 13 0f 11 0f 11 10 31 ca } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}