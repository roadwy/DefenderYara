
rule Trojan_Win32_Redline_ASAS_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b 4c 24 1c 8b c6 83 c4 08 f7 f5 8a 3c 0e 68 } //1
		$a_01_1 = {32 c3 02 c7 88 04 0e e8 } //1
		$a_01_2 = {66 64 69 6f 67 69 75 41 73 64 6f 69 48 59 55 41 55 41 59 38 37 32 33 34 } //1 fdiogiuAsdoiHYUAUAY87234
		$a_01_3 = {58 53 63 64 79 68 6a 6b 75 6a 6b 74 79 79 74 } //1 XScdyhjkujktyyt
		$a_01_4 = {75 68 67 69 79 47 41 75 79 69 73 75 61 } //1 uhgiyGAuyisua
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}