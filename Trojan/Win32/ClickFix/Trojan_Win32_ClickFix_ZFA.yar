
rule Trojan_Win32_ClickFix_ZFA{
	meta:
		description = "Trojan:Win32/ClickFix.ZFA,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //2 powershell
		$a_00_1 = {2d 00 77 00 } //2 -w
		$a_00_2 = {63 00 75 00 72 00 6c 00 } //2 curl
		$a_00_3 = {2e 00 70 00 73 00 31 00 } //-5000 .ps1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*-5000) >=6
 
}