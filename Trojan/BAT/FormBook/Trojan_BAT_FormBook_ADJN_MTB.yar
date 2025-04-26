
rule Trojan_BAT_FormBook_ADJN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ADJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 09 1b 59 } //2
		$a_01_1 = {43 00 44 00 6f 00 77 00 6e 00 } //1 CDown
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_3 = {5a 00 61 00 62 00 61 00 77 00 6b 00 69 00 } //1 Zabawki
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}