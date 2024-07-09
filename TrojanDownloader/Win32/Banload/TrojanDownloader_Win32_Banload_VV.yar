
rule TrojanDownloader_Win32_Banload_VV{
	meta:
		description = "TrojanDownloader:Win32/Banload.VV,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {61 00 73 00 2e 00 6a 00 75 00 6e 00 69 00 6f 00 72 00 31 00 39 00 38 00 38 00 2e 00 73 00 69 00 74 00 65 00 73 00 2e 00 75 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 [0-10] 2e 00 70 00 6e 00 67 00 } //10
		$a_00_1 = {6e 00 6f 00 76 00 6f 00 70 00 75 00 78 00 61 00 64 00 6f 00 72 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 novopuxador\Project1.vbp
		$a_00_2 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 57 00 69 00 6e 00 6c 00 72 00 2e 00 65 00 78 00 65 00 } //1 \system32\Winlr.exe
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=11
 
}