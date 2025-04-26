
rule Trojan_BAT_FormBook_ALD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ALD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 d2 9c 00 09 17 58 } //2
		$a_01_1 = {53 00 61 00 76 00 61 00 73 00 2e 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 } //1 Savas.Desktop
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}