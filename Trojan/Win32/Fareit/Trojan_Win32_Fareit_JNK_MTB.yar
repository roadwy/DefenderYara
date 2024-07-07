
rule Trojan_Win32_Fareit_JNK_MTB{
	meta:
		description = "Trojan:Win32/Fareit.JNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 00 04 46 01 71 01 b1 05 21 01 11 07 00 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fareit_JNK_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.JNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 56 69 65 77 4f 66 46 69 6c 65 00 04 e3 41 00 74 60 42 } //1
		$a_01_1 = {00 77 00 61 00 79 00 6e 00 65 00 2d 00 62 00 72 00 61 00 75 00 6e 00 2d 00 69 00 6e 00 76 00 65 } //1 眀愀礀渀攀ⴀ戀爀愀甀渀ⴀ椀渀瘀攀
		$a_01_2 = {00 2d 00 6d 00 61 00 73 00 74 00 65 00 72 00 5c 00 49 00 6e 00 76 00 65 00 73 00 74 00 73 00 2e 00 76 00 62 00 70 } //1 ⴀ洀愀猀琀攀爀尀䤀渀瘀攀猀琀猀⸀瘀戀瀀
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}