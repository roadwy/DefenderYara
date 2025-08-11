
rule Trojan_BAT_FormBook_BAE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 27 06 61 06 61 d2 13 27 11 28 16 61 d2 13 28 11 29 06 61 06 61 d2 13 29 11 27 13 2a 11 28 13 2b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}