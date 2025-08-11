
rule Trojan_Win32_ClickFix_ZH{
	meta:
		description = "Trojan:Win32/ClickFix.ZH,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //2 powershell
		$a_00_1 = {6d 00 73 00 68 00 74 00 61 00 } //2 mshta
		$a_00_2 = {63 00 75 00 72 00 6c 00 } //2 curl
		$a_00_3 = {68 00 74 00 74 00 70 00 } //5 http
		$a_02_4 = {69 00 77 00 72 00 [0-30] 69 00 65 00 78 00 [0-ff] 69 00 64 00 3a 00 } //5
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*5+(#a_02_4  & 1)*5) >=7
 
}