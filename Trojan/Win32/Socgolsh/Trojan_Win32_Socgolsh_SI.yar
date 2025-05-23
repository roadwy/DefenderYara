
rule Trojan_Win32_Socgolsh_SI{
	meta:
		description = "Trojan:Win32/Socgolsh.SI,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_02_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 79 00 74 00 68 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00 2f 00 66 00 74 00 70 00 [0-ff] 2e 00 7a 00 69 00 70 00 20 00 } //1
		$a_00_2 = {2d 00 6c 00 69 00 74 00 65 00 72 00 61 00 6c 00 70 00 61 00 74 00 68 00 } //1 -literalpath
		$a_00_3 = {2d 00 64 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00 } //1 -destinationpath
		$a_00_4 = {20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 62 00 6f 00 6f 00 74 00 73 00 74 00 72 00 61 00 70 00 2e 00 70 00 79 00 70 00 61 00 2e 00 69 00 6f 00 2f 00 } //1  https://bootstrap.pypa.io/
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}