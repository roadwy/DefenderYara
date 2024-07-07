
rule TrojanDownloader_Win32_VB_SQ{
	meta:
		description = "TrojanDownloader:Win32/VB.SQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 77 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //1 \system\win.exe
		$a_02_1 = {2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 90 02 10 2f 00 90 02 04 2e 00 6a 00 70 00 67 00 90 00 } //1
		$a_00_2 = {5c 00 62 00 61 00 69 00 78 00 61 00 6e 00 64 00 6f 00 34 00 6c 00 69 00 6e 00 6b 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 \baixando4link\Project1.vbp
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}