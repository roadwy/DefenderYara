
rule Trojan_Win32_ClickFix_MB_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.MB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //10 mshta
		$a_00_1 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_2 = {2d 00 20 00 43 00 41 00 50 00 54 00 43 00 48 00 41 00 } //1 - CAPTCHA
		$a_00_3 = {56 00 65 00 72 00 69 00 66 00 } //1 Verif
		$a_00_4 = {72 00 6f 00 62 00 6f 00 74 00 } //1 robot
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=14
 
}