
rule Trojan_BAT_FormBook_ABRQ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABRQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 72 ae 1d 00 70 6f 90 01 03 0a 74 90 01 03 1b 6f 90 01 03 0a 00 07 06 72 b4 1d 00 70 6f 90 01 03 0a 74 90 01 03 1b 6f 90 01 03 0a 00 07 06 72 ba 1d 00 70 6f 90 01 03 0a 74 90 01 03 1b 6f 90 01 03 0a 00 07 06 72 c0 1d 00 70 6f 90 01 03 0a 74 90 01 03 1b 6f 90 01 03 0a 00 02 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}