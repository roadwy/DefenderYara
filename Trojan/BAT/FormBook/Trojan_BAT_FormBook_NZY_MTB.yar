
rule Trojan_BAT_FormBook_NZY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 72 77 08 00 70 7e 90 01 01 00 00 0a 72 81 08 00 70 28 90 01 01 00 00 0a 18 18 8d 14 00 00 01 25 16 03 90 00 } //1
		$a_01_1 = {47 00 65 00 74 00 50 00 00 09 69 00 78 00 65 00 6c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}