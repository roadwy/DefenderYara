
rule Trojan_BAT_FormBook_ABPT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {2d 17 26 7e ?? 00 00 04 fe ?? 84 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 7d ?? 00 00 04 06 06 fe ?? 7a 00 00 06 73 ?? 00 00 0a 7d ?? 00 00 04 06 fe ?? 7b 00 00 06 73 ?? 00 00 0a 0b 07 } //5
		$a_03_1 = {25 16 0f 01 28 ?? 01 00 0a 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 0f 01 28 ?? 01 00 0a 1e 63 20 ff 00 00 00 5f d2 9c 25 18 0f 01 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}