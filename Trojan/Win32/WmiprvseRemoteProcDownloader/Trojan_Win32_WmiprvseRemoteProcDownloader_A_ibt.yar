
rule Trojan_Win32_WmiprvseRemoteProcDownloader_A_ibt{
	meta:
		description = "Trojan:Win32/WmiprvseRemoteProcDownloader.A!ibt,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 20 00 2f 00 63 00 } //1 cmd /c
		$a_00_1 = {20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1  powershell
		$a_02_2 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 6d 00 69 00 90 02 35 2f 00 70 00 6f 00 77 00 65 00 72 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}