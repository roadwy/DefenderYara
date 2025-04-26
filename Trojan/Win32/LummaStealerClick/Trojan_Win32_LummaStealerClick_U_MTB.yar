
rule Trojan_Win32_LummaStealerClick_U_MTB{
	meta:
		description = "Trojan:Win32/LummaStealerClick.U!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {61 00 64 00 64 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 } //1 add-mppreference
		$a_00_2 = {2d 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 } //1 -exclusion
		$a_00_3 = {24 00 65 00 6e 00 76 00 3a 00 } //1 $env:
		$a_00_4 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //1 net.webclient
		$a_00_5 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 } //1 .download
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}