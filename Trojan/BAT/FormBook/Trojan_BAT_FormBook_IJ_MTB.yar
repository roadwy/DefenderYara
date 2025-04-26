
rule Trojan_BAT_FormBook_IJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.IJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 59 22 00 70 6f ad 00 00 0a 13 07 11 07 09 1f 16 5d 91 13 08 07 09 91 11 08 61 13 09 09 18 58 17 59 08 5d 13 0a 07 11 0a 91 13 0b 11 09 11 0b 59 23 00 00 00 00 00 00 f0 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}