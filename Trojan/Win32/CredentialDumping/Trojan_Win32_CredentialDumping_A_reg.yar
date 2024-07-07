
rule Trojan_Win32_CredentialDumping_A_reg{
	meta:
		description = "Trojan:Win32/CredentialDumping.A!reg,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 62 00 61 00 63 00 6b 00 75 00 70 00 33 00 } //-10 regbackup3
		$a_00_1 = {5c 00 72 00 61 00 70 00 69 00 64 00 37 00 5c 00 } //-10 \rapid7\
		$a_00_2 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 } //1 reg.exe
		$a_00_3 = {20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 } //1  save hklm\system 
		$a_00_4 = {20 00 5c 00 5c 00 74 00 73 00 63 00 6c 00 69 00 65 00 6e 00 74 00 5c 00 } //1  \\tsclient\
	condition:
		((#a_00_0  & 1)*-10+(#a_00_1  & 1)*-10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}