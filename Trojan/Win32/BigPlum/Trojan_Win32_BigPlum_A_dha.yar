
rule Trojan_Win32_BigPlum_A_dha{
	meta:
		description = "Trojan:Win32/BigPlum.A!dha,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //4 powershell
		$a_00_1 = {77 00 68 00 6f 00 61 00 6d 00 69 00 } //1 whoami
		$a_00_2 = {6e 00 65 00 74 00 73 00 74 00 61 00 74 00 } //1 netstat
		$a_00_3 = {63 00 75 00 72 00 6c 00 } //1 curl
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}