
rule Trojan_BAT_FormBook_AHAN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AHAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 11 04 6f ?? ?? ?? 0a 13 06 20 ff 00 00 00 20 ff 00 00 00 12 06 28 ?? ?? ?? 0a 59 20 ff 00 00 00 12 06 } //2
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 65 00 79 00 72 00 2e 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Softweyr.Configuration
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}