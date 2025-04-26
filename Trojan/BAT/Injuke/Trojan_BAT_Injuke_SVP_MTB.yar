
rule Trojan_BAT_Injuke_SVP_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 7e 07 00 00 04 11 02 7e 07 00 00 04 8e 69 5d 91 02 11 02 91 61 d2 6f ?? ?? ?? 0a 38 5a 00 00 00 11 02 02 8e 69 3f d4 ff ff ff 20 00 00 00 00 7e 41 00 00 04 7b 46 00 00 04 39 93 ff ff ff 26 20 00 00 00 00 38 88 ff ff ff 38 d2 ff ff ff 20 03 00 00 00 38 79 ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}