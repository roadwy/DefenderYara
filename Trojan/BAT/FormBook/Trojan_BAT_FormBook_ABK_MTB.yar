
rule Trojan_BAT_FormBook_ABK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 58 0b 2b 49 07 06 8e 69 5d 13 04 07 09 6f 90 01 03 0a 5d 13 09 06 11 04 91 13 0a 09 11 09 6f 90 01 03 0a 13 0b 02 06 07 28 90 01 03 06 13 0c 02 11 0a 11 0b 11 0c 28 90 01 03 06 13 0d 06 11 04 02 11 0d 28 90 01 03 06 9c 07 17 59 0b 07 16 fe 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}