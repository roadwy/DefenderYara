
rule Trojan_Win32_RundllLolBin_AI{
	meta:
		description = "Trojan:Win32/RundllLolBin.AI,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_1 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 -command
		$a_00_2 = {69 00 65 00 78 00 } //1 iex
		$a_00_3 = {75 00 74 00 66 00 38 00 2e 00 67 00 65 00 74 00 73 00 74 00 72 00 69 00 6e 00 67 00 } //1 utf8.getstring
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}