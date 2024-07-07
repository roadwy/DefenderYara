
rule Trojan_BAT_Darkcloud_AALE_MTB{
	meta:
		description = "Trojan:BAT/Darkcloud.AALE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 8e 69 17 da 13 0f 16 13 10 2b 25 11 06 11 10 17 8d 90 01 01 00 00 01 25 16 11 05 11 10 9a 1f 10 28 90 01 01 00 00 0a 9c 6f 90 01 01 00 00 0a 00 11 10 17 d6 13 10 11 10 11 0f 31 d5 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}