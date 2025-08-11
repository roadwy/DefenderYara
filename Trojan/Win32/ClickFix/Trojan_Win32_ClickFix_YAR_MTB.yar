
rule Trojan_Win32_ClickFix_YAR_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.YAR!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,2f 01 2f 01 06 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 } //100 curl.exe
		$a_00_1 = {68 00 74 00 74 00 70 00 } //100 http
		$a_00_2 = {63 00 6d 00 64 00 20 00 2f 00 63 00 } //100 cmd /c
		$a_00_3 = {76 00 65 00 72 00 69 00 66 00 79 00 } //1 verify
		$a_00_4 = {79 00 6f 00 75 00 72 00 65 00 } //1 youre
		$a_00_5 = {68 00 75 00 6d 00 61 00 6e 00 } //1 human
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=303
 
}