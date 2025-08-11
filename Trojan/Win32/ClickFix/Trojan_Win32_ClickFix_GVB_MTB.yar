
rule Trojan_Win32_ClickFix_GVB_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GVB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_00_0 = {69 00 65 00 78 00 } //1 iex
		$a_00_1 = {68 00 74 00 74 00 70 00 } //10 http
		$a_00_2 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //10 net.webclient
		$a_00_3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 } //10 download
		$a_00_4 = {63 00 75 00 72 00 6c 00 } //10 curl
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10) >=21
 
}