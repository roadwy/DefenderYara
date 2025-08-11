
rule Trojan_BAT_FormBook_VGG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.VGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 da 26 00 00 28 ?? 02 00 06 28 ?? 00 00 0a 0a 20 95 23 00 00 28 92 02 00 06 28 0f 00 00 0a 0b 73 10 00 00 0a 0c 73 11 00 00 0a 0d 09 08 06 07 6f 12 00 00 0a 17 73 13 00 00 0a 13 04 11 04 03 16 03 8e 69 6f 14 00 00 0a 09 6f ?? 00 00 0a 13 05 de 20 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}