
rule Trojan_BAT_FormBook_ESD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ESD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 03 04 20 00 04 01 00 5d 03 02 20 00 04 01 00 04 90 01 05 03 04 17 58 20 00 04 01 00 5d 91 90 01 05 59 06 58 06 5d 90 01 05 9c 03 0b 07 2a 90 00 } //1
		$a_03_1 = {02 05 04 5d 91 03 05 1f 16 5d 90 01 05 61 90 01 05 0a 06 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}