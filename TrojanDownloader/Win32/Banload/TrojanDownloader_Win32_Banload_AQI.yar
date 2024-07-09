
rule TrojanDownloader_Win32_Banload_AQI{
	meta:
		description = "TrojanDownloader:Win32/Banload.AQI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f [0-0a] 2f 61 2e 67 69 66 } //1
		$a_00_1 = {73 69 73 74 65 6d 61 6e 65 74 00 } //1
		$a_01_2 = {00 2e 65 78 65 00 00 00 00 00 00 00 00 6f 70 65 6e 00 } //1
		$a_02_3 = {80 7c 30 ff 2f 75 d2 8d 85 44 fe ff ff 50 68 01 01 00 00 e8 ?? ?? ?? ?? 6a 00 6a 01 6a 02 e8 ?? ?? ?? ?? 8b f0 66 c7 85 34 fe ff ff 02 00 83 ff 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}