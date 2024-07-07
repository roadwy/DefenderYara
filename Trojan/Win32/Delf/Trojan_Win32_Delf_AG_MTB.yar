
rule Trojan_Win32_Delf_AG_MTB{
	meta:
		description = "Trojan:Win32/Delf.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 53 6f 63 6b 20 32 2e 30 } //1 WinSock 2.0
		$a_01_1 = {4d 50 47 6f 6f 64 53 74 61 74 75 73 } //1 MPGoodStatus
		$a_01_2 = {73 6c 61 73 68 5c 55 73 65 72 } //1 slash\User
		$a_01_3 = {4e 65 77 20 55 73 65 72 6f 77 6e 6c 6f 61 64 73 5c 54 68 65 } //1 New Userownloads\The
		$a_01_4 = {73 6c 61 73 68 2e 65 78 65 6d 61 73 74 65 72 5c } //1 slash.exemaster\
		$a_01_5 = {73 6c 61 73 68 74 74 69 6e 67 73 2e 69 6e 69 } //1 slashttings.ini
		$a_01_6 = {34 36 2e 32 34 36 2e 31 32 32 2e 31 38 38 23 50 41 44 } //1 46.246.122.188#PAD
		$a_01_7 = {47 65 74 41 43 50 } //1 GetACP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}