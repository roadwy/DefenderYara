
rule Trojan_BAT_Darkcloud_PGDK_MTB{
	meta:
		description = "Trojan:BAT/Darkcloud.PGDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 7b 00 01 00 04 11 06 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 07 19 8d ?? 00 00 01 25 16 12 07 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a 9c 7e ?? 00 00 04 25 2d 17 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}