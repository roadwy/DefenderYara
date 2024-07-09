
rule Trojan_BAT_FormBook_ABUB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABUB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 1f 00 09 08 11 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 07 18 58 13 07 11 07 08 6f ?? 00 00 0a fe 04 13 08 11 08 2d d1 } //4
		$a_01_1 = {47 00 61 00 6d 00 65 00 58 00 4f 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 GameXO.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}