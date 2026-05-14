
rule Trojan_BAT_XWorm_ABXW_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ABXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 07 11 08 6f ?? 00 00 0a 13 0b 05 39 ?? 01 00 00 11 0b 73 ?? 00 00 06 13 0f 7e ?? 00 00 04 2d 25 } //5
		$a_03_1 = {13 0c 12 0b 28 ?? 00 00 0a 13 0d 12 0b 28 ?? 00 00 0a 13 0e 08 11 0c 11 07 11 08 58 6f ?? 00 00 06 13 0c 08 11 0d 11 08 11 07 58 6f ?? 00 00 06 13 0d 08 11 0e 11 07 11 08 61 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}