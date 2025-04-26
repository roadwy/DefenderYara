
rule Trojan_BAT_FormBook_EWAA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EWAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 08 91 08 11 09 91 61 13 0b 11 0b 07 11 0a 91 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0c 07 11 08 11 0c d2 9c 11 05 17 58 13 05 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}