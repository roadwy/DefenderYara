
rule Trojan_Win32_ClickFix_STB{
	meta:
		description = "Trojan:Win32/ClickFix.STB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_00_1 = {20 00 23 00 20 00 } //1  # 
		$a_00_2 = {3a 00 2f 00 2f 00 } //1 ://
		$a_00_3 = {2e 00 6f 00 67 00 67 00 20 00 23 00 } //1 .ogg #
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Trojan_Win32_ClickFix_STB_2{
	meta:
		description = "Trojan:Win32/ClickFix.STB,SIGNATURE_TYPE_CMDHSTR_EXT,2d 01 2d 01 08 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //100 mshta
		$a_00_1 = {20 00 23 00 20 00 } //100  # 
		$a_00_2 = {3a 00 2f 00 2f 00 } //100 ://
		$a_00_3 = {63 00 6f 00 6e 00 66 00 69 00 72 00 6d 00 } //1 confirm
		$a_00_4 = {63 00 61 00 70 00 74 00 63 00 68 00 61 00 } //1 captcha
		$a_00_5 = {68 00 75 00 6d 00 61 00 6e 00 } //1 human
		$a_00_6 = {72 00 6f 00 62 00 6f 00 74 00 } //1 robot
		$a_00_7 = {76 00 65 00 72 00 69 00 66 00 } //1 verif
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=301
 
}