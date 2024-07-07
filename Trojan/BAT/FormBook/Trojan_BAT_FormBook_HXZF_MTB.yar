
rule Trojan_BAT_FormBook_HXZF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.HXZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 28 90 01 03 06 13 05 08 09 11 04 6f 90 01 03 0a 13 06 11 06 28 90 01 03 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 08 11 08 2d c8 90 00 } //2
		$a_01_1 = {53 00 61 00 6e 00 64 00 62 00 6f 00 78 00 44 00 6f 00 74 00 4e 00 65 00 74 00 } //1 SandboxDotNet
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}