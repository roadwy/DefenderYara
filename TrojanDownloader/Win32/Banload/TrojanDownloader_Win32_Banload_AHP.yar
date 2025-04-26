
rule TrojanDownloader_Win32_Banload_AHP{
	meta:
		description = "TrojanDownloader:Win32/Banload.AHP,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 00 65 00 74 00 69 00 6d 00 5f 00 6c 00 6f 00 61 00 64 00 5f 00 76 00 62 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 vetim_load_vb\Project1.vbp
		$a_01_1 = {73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 6e 00 67 00 72 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //1 system32\msngrss.exe
		$a_01_2 = {63 68 69 6e 61 20 63 72 61 63 6b 69 6e 67 20 67 72 6f 75 70 } //1 china cracking group
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}