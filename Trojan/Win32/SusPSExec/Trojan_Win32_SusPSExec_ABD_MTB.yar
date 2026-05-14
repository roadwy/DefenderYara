
rule Trojan_Win32_SusPSExec_ABD_MTB{
	meta:
		description = "Trojan:Win32/SusPSExec.ABD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_1 = {69 00 72 00 6d 00 } //1 irm
		$a_00_2 = {65 00 6d 00 65 00 64 00 69 00 74 00 6f 00 72 00 6a 00 70 00 2e 00 63 00 6f 00 6d 00 } //1 emeditorjp.com
		$a_00_3 = {7c 00 20 00 69 00 65 00 78 00 } //1 | iex
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}