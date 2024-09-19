
rule Trojan_BAT_FormBook_NQ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {1f 16 5d 91 13 08 07 11 06 91 11 08 61 13 09 11 06 17 58 08 5d 13 0a 07 11 0a 91 } //10
		$a_01_1 = {17 59 5f 13 0d 07 11 06 11 0d d2 9c 00 11 06 17 58 13 06 11 06 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}