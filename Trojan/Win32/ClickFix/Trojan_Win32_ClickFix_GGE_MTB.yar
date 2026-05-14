
rule Trojan_Win32_ClickFix_GGE_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GGE!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {77 00 67 00 65 00 74 00 } //1 wget
		$a_00_1 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_2 = {63 00 6d 00 64 00 2e 00 63 00 6d 00 64 00 } //1 cmd.cmd
		$a_00_3 = {2e 00 70 00 68 00 70 00 } //1 .php
		$a_00_4 = {73 00 74 00 61 00 72 00 74 00 } //1 start
		$a_00_5 = {6a 00 70 00 63 00 69 00 6d 00 65 00 76 00 74 00 2e 00 65 00 78 00 65 00 } //-100 jpcimevt.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*-100) >=5
 
}