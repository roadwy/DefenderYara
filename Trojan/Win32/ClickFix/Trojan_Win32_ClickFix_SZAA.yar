
rule Trojan_Win32_ClickFix_SZAA{
	meta:
		description = "Trojan:Win32/ClickFix.SZAA,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_02_1 = {69 00 65 00 78 00 28 00 69 00 77 00 72 00 [0-10] 2d 00 75 00 72 00 69 00 [0-30] 90 29 03 00 2e 00 90 29 03 00 2e 00 90 29 03 00 2e 00 90 29 03 00 } //1
		$a_00_2 = {2d 00 75 00 73 00 65 00 62 00 } //1 -useb
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}