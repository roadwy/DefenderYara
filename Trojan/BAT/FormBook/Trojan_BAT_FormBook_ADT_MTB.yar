
rule Trojan_BAT_FormBook_ADT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 16 e0 00 00 0c 2b 16 20 b3 f4 85 b5 28 90 01 03 06 07 08 28 90 01 03 06 0b 08 15 58 0c 08 16 fe 04 16 fe 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}