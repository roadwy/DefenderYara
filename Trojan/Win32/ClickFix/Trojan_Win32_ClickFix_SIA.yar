
rule Trojan_Win32_ClickFix_SIA{
	meta:
		description = "Trojan:Win32/ClickFix.SIA,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 [0-10] 2f 00 63 00 [0-30] 63 00 75 00 72 00 6c 00 } //10
		$a_00_1 = {68 00 74 00 74 00 70 00 } //10 http
		$a_00_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_3 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=21
 
}