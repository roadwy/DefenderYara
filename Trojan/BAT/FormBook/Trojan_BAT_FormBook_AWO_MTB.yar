
rule Trojan_BAT_FormBook_AWO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AWO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 16 0c 2b 4e 00 02 08 6f 4a 00 00 0a 0d 09 20 a7 00 00 00 fe 01 13 04 11 04 2c 32 00 02 07 08 07 59 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}