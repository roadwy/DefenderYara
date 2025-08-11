
rule Trojan_BAT_FormBook_BAC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 07 08 07 08 91 19 63 07 08 91 1b 62 60 d2 9c 08 17 58 0c 08 02 8e 69 32 d8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}