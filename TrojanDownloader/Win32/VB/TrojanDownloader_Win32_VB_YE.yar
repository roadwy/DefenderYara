
rule TrojanDownloader_Win32_VB_YE{
	meta:
		description = "TrojanDownloader:Win32/VB.YE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 00 43 00 3a 00 5c 00 70 00 75 00 78 00 61 00 5c 00 6c 00 65 00 6e 00 64 00 61 00 2e 00 76 00 62 00 70 00 } //1 AC:\puxa\lenda.vbp
		$a_01_1 = {6c 00 6f 00 61 00 64 00 65 00 72 00 5f 00 72 00 6f 00 62 00 65 00 72 00 78 00 2e 00 65 00 78 00 65 00 } //1 loader_roberx.exe
		$a_03_2 = {4f 70 65 6e 48 54 54 50 [0-0a] 43 6c 6f 73 65 48 54 54 50 [0-0a] 53 65 6e 64 52 65 71 75 65 73 74 [0-0a] 55 52 4c 45 6e 63 6f 64 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}