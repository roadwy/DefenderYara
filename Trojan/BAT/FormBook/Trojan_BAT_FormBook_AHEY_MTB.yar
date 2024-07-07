
rule Trojan_BAT_FormBook_AHEY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AHEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 06 1c 20 c3 00 00 00 9c 06 1a 20 80 00 00 00 9c 06 19 1d 9c 06 18 16 9c 06 1b 20 c3 00 00 00 9c 06 17 1f 57 9c 06 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}