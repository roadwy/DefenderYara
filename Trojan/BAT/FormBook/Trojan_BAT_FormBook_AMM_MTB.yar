
rule Trojan_BAT_FormBook_AMM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 11 07 9a 0d 08 09 6f 35 00 00 0a 6f 24 00 00 0a 03 6f 89 00 00 0a 39 07 00 00 00 08 09 6f 8a 00 00 0a 11 07 17 d6 13 07 11 07 11 08 8e b7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}