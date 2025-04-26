
rule Trojan_BAT_FormBook_BAA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 6f 47 02 00 0a 26 04 07 08 91 6f 48 02 00 0a 08 17 58 0c 08 03 32 e7 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}