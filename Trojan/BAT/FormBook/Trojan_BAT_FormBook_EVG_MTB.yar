
rule Trojan_BAT_FormBook_EVG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 02 8e 69 17 59 91 1f 70 61 13 04 02 8e 69 17 58 } //1
		$a_01_1 = {02 07 91 11 04 61 09 06 91 61 13 05 08 07 11 05 d2 9c 06 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}