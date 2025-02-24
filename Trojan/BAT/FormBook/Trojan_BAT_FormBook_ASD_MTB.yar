
rule Trojan_BAT_FormBook_ASD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 44 00 00 0a 13 26 12 26 28 45 00 00 0a 11 0b 5a 73 46 00 00 0a 11 0e 6f 47 00 00 0a 00 02 09 11 0b 11 0d 2d 08 11 0e 16 91 17 5d 2b 01 16 58 28 0c 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}