
rule Trojan_Win32_DiscoveryViaCmd_A{
	meta:
		description = "Trojan:Win32/DiscoveryViaCmd.A,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_02_0 = {71 00 75 00 65 00 72 00 79 00 20 00 73 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 3e 00 [0-02] 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 [0-10] 2e 00 74 00 6d 00 70 00 } //1
		$a_02_1 = {67 00 70 00 72 00 65 00 73 00 75 00 6c 00 74 00 20 00 2f 00 76 00 20 00 3e 00 20 00 [0-02] 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 [0-20] 2e 00 74 00 78 00 74 00 } //1
		$a_00_2 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 } //6 :\windows\system32\cmd.exe /c
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*6) >=7
 
}