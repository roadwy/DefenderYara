
rule HackTool_Win32_Silentall{
	meta:
		description = "HackTool:Win32/Silentall,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 69 00 6c 00 65 00 6e 00 74 00 41 00 6c 00 6c 00 2e 00 4e 00 65 00 74 00 20 00 4b 00 61 00 74 00 } //1 SilentAll.Net Kat
		$a_01_1 = {53 69 6c 65 6e 74 41 4c 4c 53 61 6d 70 6c 65 50 72 6f 6a 65 63 74 2e 50 72 6f 70 65 72 74 69 65 73 } //1 SilentALLSampleProject.Properties
		$a_01_2 = {75 00 54 00 6f 00 72 00 72 00 65 00 6e 00 74 00 } //1 uTorrent
		$a_01_3 = {42 00 69 00 74 00 54 00 6f 00 72 00 72 00 65 00 6e 00 74 00 } //1 BitTorrent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}