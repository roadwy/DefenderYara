
rule Trojan_Win32_Darkpus_A{
	meta:
		description = "Trojan:Win32/Darkpus.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 50 72 65 66 65 72 65 6e 63 65 73 5c 6b 65 79 63 68 61 69 6e 2e 70 6c 69 73 74 } //1 \Preferences\keychain.plist
		$a_00_1 = {5c 57 53 5f 46 54 50 5c 53 69 74 65 73 5c 77 73 5f 66 74 70 2e 69 6e 69 } //1 \WS_FTP\Sites\ws_ftp.ini
		$a_00_2 = {00 75 70 6c 6f 61 64 2e 70 68 70 00 } //1
		$a_01_3 = {54 42 6f 74 54 68 72 65 61 64 5f } //1 TBotThread_
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}