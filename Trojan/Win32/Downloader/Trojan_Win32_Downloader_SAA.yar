
rule Trojan_Win32_Downloader_SAA{
	meta:
		description = "Trojan:Win32/Downloader.SAA,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {61 00 67 00 65 00 6e 00 74 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 66 00 69 00 6c 00 65 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 agentpackagefileexplorer.exe
		$a_00_1 = {61 00 67 00 65 00 6e 00 74 00 2d 00 61 00 70 00 69 00 2e 00 61 00 74 00 65 00 72 00 61 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 } //1 agent-api.atera.com/production
		$a_00_2 = {6f 00 72 00 38 00 69 00 78 00 6c 00 69 00 39 00 30 00 6d 00 66 00 } //1 or8ixli90mf
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}