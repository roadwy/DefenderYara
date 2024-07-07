
rule Trojan_Win32_VaultCredentials_B{
	meta:
		description = "Trojan:Win32/VaultCredentials.B,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 01 00 04 00 00 "
		
	strings :
		$a_80_0 = {76 61 75 6c 74 63 6d 64 2e 65 78 65 20 2f 6c 69 73 74 63 72 65 64 73 3a } //vaultcmd.exe /listcreds:  1
		$a_80_1 = {76 61 75 6c 74 63 6d 64 20 2f 6c 69 73 74 63 72 65 64 73 3a } //vaultcmd /listcreds:  1
		$a_80_2 = {76 61 75 6c 74 63 6d 64 2e 65 78 65 20 2f 6c 69 73 74 } //vaultcmd.exe /list  1
		$a_80_3 = {76 61 75 6c 74 63 6d 64 20 2f 6c 69 73 74 } //vaultcmd /list  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=1
 
}