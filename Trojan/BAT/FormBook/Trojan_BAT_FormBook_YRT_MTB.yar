
rule Trojan_BAT_FormBook_YRT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.YRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 72 61 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 20 03 00 00 00 fe 0e 04 00 38 00 00 00 00 fe 0c 04 00 45 04 00 00 00 2d 00 00 00 83 00 00 00 05 00 00 00 53 00 00 00 38 28 00 00 00 11 00 6f ?? 00 00 0a 13 01 20 00 00 00 00 7e 96 00 00 04 7b 62 00 00 04 3a c9 ff ff ff 26 20 00 00 00 00 38 be ff ff ff 73 16 00 00 0a 13 09 20 01 00 00 00 7e 96 00 00 04 7b 53 00 00 04 3a a3 ff ff ff 26 20 00 00 00 00 38 98 ff ff ff 11 00 72 93 00 00 70 28 13 00 00 0a 6f 17 00 00 0a 20 01 00 00 00 7e 96 00 00 04 7b 88 00 00 04 3a 73 ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}