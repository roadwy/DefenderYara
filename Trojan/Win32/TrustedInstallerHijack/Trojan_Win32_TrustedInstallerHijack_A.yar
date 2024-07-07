
rule Trojan_Win32_TrustedInstallerHijack_A{
	meta:
		description = "Trojan:Win32/TrustedInstallerHijack.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 74 00 72 00 75 00 73 00 74 00 65 00 64 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 20 00 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 90 02 02 3d 00 90 00 } //1
		$a_00_1 = {3a 00 5c 00 6c 00 65 00 6e 00 6f 00 76 00 6f 00 71 00 75 00 69 00 63 00 6b 00 66 00 69 00 78 00 5c 00 } //65535 :\lenovoquickfix\
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*65535) >=1
 
}
rule Trojan_Win32_TrustedInstallerHijack_A_2{
	meta:
		description = "Trojan:Win32/TrustedInstallerHijack.A,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 74 00 72 00 75 00 73 00 74 00 65 00 64 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 20 00 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 90 02 02 3d 00 90 00 } //1
		$a_00_1 = {3a 00 5c 00 6c 00 65 00 6e 00 6f 00 76 00 6f 00 71 00 75 00 69 00 63 00 6b 00 66 00 69 00 78 00 5c 00 } //65535 :\lenovoquickfix\
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*65535) >=1
 
}