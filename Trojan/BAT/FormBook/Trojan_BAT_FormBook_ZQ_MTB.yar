
rule Trojan_BAT_FormBook_ZQ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 c3 00 00 70 6f 5b 00 00 0a 13 0b 11 0b 11 08 1f 16 5d 91 13 0c 11 06 11 08 91 11 0c 61 13 0d 11 06 11 08 17 58 11 07 5d 91 13 0e 11 0d 11 0e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}