
rule TrojanDownloader_Win32_Banload_BBO{
	meta:
		description = "TrojanDownloader:Win32/Banload.BBO,SIGNATURE_TYPE_PEHSTR,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 39 32 2e 31 36 39 2e 39 30 2e 32 39 } //5 http://192.169.90.29
		$a_01_1 = {61 63 72 6f 6e 79 6d 73 6c 65 6b 73 2e 65 78 65 } //1 acronymsleks.exe
		$a_01_2 = {67 75 6e 79 6f 75 74 6c 2e 65 78 65 } //1 gunyoutl.exe
		$a_01_3 = {41 73 77 61 6e 79 6f 75 2e 65 78 65 } //1 Aswanyou.exe
		$a_01_4 = {55 73 65 73 5f 70 63 2e 7a 6c 69 62 } //1 Uses_pc.zlib
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}