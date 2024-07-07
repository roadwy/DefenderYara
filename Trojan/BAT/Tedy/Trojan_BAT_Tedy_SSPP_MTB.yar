
rule Trojan_BAT_Tedy_SSPP_MTB{
	meta:
		description = "Trojan:BAT/Tedy.SSPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 08 6f 90 01 03 06 08 6f 90 01 03 06 11 04 8f 0a 00 00 02 7b 8e 00 00 04 11 05 08 6f 90 01 03 06 11 04 8f 0a 00 00 02 7b 8d 00 00 04 28 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 08 6f 90 01 03 06 7b 84 00 00 04 fe 04 13 2a 11 2a 3a 73 ff ff ff 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}