
rule Trojan_Win32_Redline_GPAC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GPAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {32 fb 8a 1c 06 68 } //1
		$a_81_1 = {66 64 69 6f 67 69 75 41 73 64 6f 69 48 59 55 41 55 41 59 38 37 32 33 34 } //1 fdiogiuAsdoiHYUAUAY87234
		$a_81_2 = {64 69 6a 6f 76 68 79 75 47 53 59 59 53 79 75 73 } //1 dijovhyuGSYYSyus
		$a_81_3 = {73 75 69 68 38 39 41 68 33 } //1 suih89Ah3
		$a_81_4 = {58 53 63 64 79 68 6a 6b 75 6a 6b 74 79 79 74 } //1 XScdyhjkujktyyt
		$a_81_5 = {73 4a 42 43 73 4b 4a 32 42 4a 4e } //1 sJBCsKJ2BJN
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}