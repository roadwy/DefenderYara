
rule Trojan_BAT_FormBook_USR_MTB{
	meta:
		description = "Trojan:BAT/FormBook.USR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 16 e0 00 00 0c 2b 16 20 d7 4a 55 4d 28 90 01 03 06 07 08 28 90 01 03 06 0b 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d df 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}