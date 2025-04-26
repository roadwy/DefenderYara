
rule TrojanDownloader_Win32_Banload_AWI{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 0f b6 44 30 ff 33 c3 89 45 e0 3b 7d e0 7c 0f 8b 45 e0 } //4
		$a_01_1 = {5c 63 6d 64 2e 65 78 65 20 2f 6b 20 72 65 67 73 76 72 33 32 2e 65 78 65 20 20 22 } //1 \cmd.exe /k regsvr32.exe  "
		$a_01_2 = {61 70 6c 69 63 61 74 69 76 6f 73 5c } //1 aplicativos\
		$a_01_3 = {32 2e 6a 70 67 22 } //1 2.jpg"
		$a_01_4 = {35 2e 63 70 6c } //1 5.cpl
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}
rule TrojanDownloader_Win32_Banload_AWI_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWI,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_02_0 = {35 2e 63 70 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 2e 74 78 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 2e 6a 70 67 } //10
		$a_02_1 = {4f 4e 5c 52 55 4e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 3a 5c 57 69 6e 64 6f 77 73 5c 53 } //1
		$a_00_2 = {00 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 00 } //1 愀慴剜慯業杮\
		$a_00_3 = {54 63 61 62 65 63 61 64 6f 6d 65 75 70 61 75 } //1 Tcabecadomeupau
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=12
 
}