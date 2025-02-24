
rule Trojan_Win32_PsCurlExec_A_MTB{
	meta:
		description = "Trojan:Win32/PsCurlExec.A!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
		$a_00_2 = {63 00 75 00 72 00 6c 00 } //1 curl
		$a_00_3 = {7c 00 20 00 69 00 65 00 78 00 } //1 | iex
		$a_00_4 = {68 00 74 00 74 00 70 00 90 00 02 00 50 00 2e 00 70 00 68 00 70 00 3f 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}