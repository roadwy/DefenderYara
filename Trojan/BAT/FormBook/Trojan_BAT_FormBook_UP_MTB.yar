
rule Trojan_BAT_FormBook_UP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.UP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 9f 25 00 70 18 17 8d 19 00 00 01 25 16 07 a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 26 07 28 ?? ?? ?? 0a 0a 2b 00 06 2a } //1
		$a_01_1 = {42 00 75 00 6e 00 69 00 66 00 75 00 5f 00 54 00 65 00 78 00 74 00 42 00 6f 00 78 00 } //1 Bunifu_TextBox
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}