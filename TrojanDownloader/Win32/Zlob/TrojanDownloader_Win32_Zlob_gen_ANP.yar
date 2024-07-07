
rule TrojanDownloader_Win32_Zlob_gen_ANP{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!ANP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 6c 75 62 72 69 63 2e 64 6c 6c } //1 \lubric.dll
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 57 65 62 4d 65 64 69 61 56 69 65 77 65 72 } //1 Software\WebMediaViewer
		$a_01_2 = {7b 46 30 30 45 35 39 46 39 } //1 {F00E59F9
		$a_01_3 = {57 65 62 20 4d 65 64 69 61 20 56 69 65 77 65 72 20 49 6e 73 74 61 6c 6c 65 72 20 61 6c 72 65 61 64 79 20 69 6e 73 74 61 6c 6c 65 64 } //1 Web Media Viewer Installer already installed
		$a_01_4 = {6d 75 74 6f 62 72 6f 6e 63 } //1 mutobronc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}