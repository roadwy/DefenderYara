
rule TrojanDownloader_Win32_TwinCarbon_A_dha{
	meta:
		description = "TrojanDownloader:Win32/TwinCarbon.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 20 64 6f 77 6e 6c 6f 61 64 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 3a 20 } //1 File downloaded successfully: 
		$a_01_1 = {54 68 65 20 66 69 6c 65 20 69 73 20 61 20 50 4e 47 20 69 6d 61 67 65 2e } //1 The file is a PNG image.
		$a_01_2 = {2c 20 44 6f 55 70 64 61 74 65 49 6e 73 74 61 6e 63 65 45 78 } //1 , DoUpdateInstanceEx
		$a_01_3 = {46 61 69 6c 65 64 20 74 6f 20 63 61 6c 6c 20 74 68 65 20 44 4c 4c 20 66 75 6e 63 74 69 6f 6e 2e } //1 Failed to call the DLL function.
		$a_01_4 = {46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 6f 75 74 70 75 74 20 66 69 6c 65 2e } //1 Failed to open output file.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}