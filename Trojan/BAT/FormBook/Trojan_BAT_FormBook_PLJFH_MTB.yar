
rule Trojan_BAT_FormBook_PLJFH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PLJFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 02 ?? 00 00 ff 00 5f 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 02 20 ?? ff 00 00 5f 1e 63 20 ff 00 00 00 5f d2 9c 25 18 02 20 ff 00 00 00 5f 20 ff 00 00 00 5f d2 9c 13 05 2b 00 11 05 2a } //6
		$a_03_1 = {0a 1f 10 62 0f 00 28 ?? 00 00 0a 1e 62 60 0f 00 28 ?? 00 00 0a 60 0b 2b 00 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}