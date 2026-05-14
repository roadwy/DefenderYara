
rule Trojan_BAT_FormBook_PAE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 05 0e 04 6f ?? 00 00 0a 0a 03 6f ?? 00 00 0a 19 58 04 30 08 03 06 28 10 00 00 06 2a } //3
		$a_01_1 = {20 00 1e 01 00 73 } //1  Ğ猀
		$a_81_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=5
 
}