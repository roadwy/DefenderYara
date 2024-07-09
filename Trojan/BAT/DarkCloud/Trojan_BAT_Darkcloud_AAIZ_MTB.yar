
rule Trojan_BAT_Darkcloud_AAIZ_MTB{
	meta:
		description = "Trojan:BAT/Darkcloud.AAIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 06 8e 69 5d 06 07 06 8e 69 5d 91 09 07 1f 16 5d 6f ?? 00 00 0a 61 06 07 17 58 06 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 07 15 58 0b 07 16 fe 04 16 fe 01 13 06 11 06 2d bf } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}