
rule Trojan_BAT_FormBook_AE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0c 07 17 59 8d 62 00 00 01 0d 02 09 16 07 17 59 6f 78 00 00 0a 26 09 73 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}