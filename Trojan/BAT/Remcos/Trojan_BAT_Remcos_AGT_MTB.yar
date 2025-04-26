
rule Trojan_BAT_Remcos_AGT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 08 8e 69 17 da 0d 09 13 04 2b 16 07 08 11 04 93 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 11 04 15 d6 13 04 11 04 16 2f e5 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {41 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 5f 00 48 00 74 00 6d 00 6c 00 5f 00 45 00 64 00 69 00 74 00 6f 00 72 00 } //1 Advanced_Html_Editor
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}