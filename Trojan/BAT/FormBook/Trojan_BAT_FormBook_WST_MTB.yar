
rule Trojan_BAT_FormBook_WST_MTB{
	meta:
		description = "Trojan:BAT/FormBook.WST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 07 11 05 94 02 5a 1f 64 5d 9e 11 0a 20 ?? 80 37 a9 5a 20 b1 df 46 f9 61 38 ?? fe ff ff 16 13 05 11 0a 20 0c 52 4f b1 5a 20 53 2e 79 70 61 38 3c fe ff ff 16 0c 11 0a 20 f8 95 3c 22 5a 20 81 c5 06 04 61 38 27 fe ff ff 11 07 07 8e 69 fe 04 13 08 11 08 2d 08 20 62 9f a8 93 25 2b 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}