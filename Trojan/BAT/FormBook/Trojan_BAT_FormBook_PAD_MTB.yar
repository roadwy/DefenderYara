
rule Trojan_BAT_FormBook_PAD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 06 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 } //3
		$a_01_1 = {06 20 00 ee 00 00 28 3e } //1
		$a_81_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=5
 
}