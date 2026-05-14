
rule Trojan_BAT_XWorm_WSA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.WSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0e 04 17 59 13 07 1f 0f 13 10 38 5b fe ff ff 11 06 74 ?? 00 00 1b 11 07 8f 4a 00 00 01 25 71 4a 00 00 01 11 07 0e 04 58 05 59 20 ff 00 00 00 5f d2 61 d2 81 4a 00 00 01 1c 13 10 38 2a fe ff ff 11 07 17 59 13 07 1f 0f 13 10 38 1b fe ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}