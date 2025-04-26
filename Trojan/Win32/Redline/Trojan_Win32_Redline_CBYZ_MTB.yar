
rule Trojan_Win32_Redline_CBYZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.CBYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 41 48 55 4a 49 73 67 41 59 48 55 64 67 61 65 79 75 77 65 66 32 36 37 } //1 sAHUJIsgAYHUdgaeyuwef267
		$a_01_1 = {58 53 66 72 74 75 6a 36 37 36 37 } //1 XSfrtuj6767
		$a_01_2 = {73 49 55 48 7a 75 69 41 42 78 72 } //1 sIUHzuiABxr
		$a_01_3 = {36 79 72 77 65 72 66 67 64 75 79 71 77 66 64 67 33 65 } //1 6yrwerfgduyqwfdg3e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}