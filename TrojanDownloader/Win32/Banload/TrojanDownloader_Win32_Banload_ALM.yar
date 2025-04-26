
rule TrojanDownloader_Win32_Banload_ALM{
	meta:
		description = "TrojanDownloader:Win32/Banload.ALM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 69 6c 65 73 75 70 64 6f 77 6e [0-0a] 68 74 74 70 3a 2f 2f 31 38 39 2e 33 36 2e 31 33 37 2e 38 32 2f 69 6d 61 67 65 6e 73 2f 6e 6f 74 69 63 69 61 73 2f 76 69 73 69 74 61 2f 45 4e 2f 4d 79 53 71 6c 2f 65 6e 64 6e 6e 65 77 2f } //1
		$a_01_1 = {5c 6d 73 6e 6d 73 67 67 72 32 2e 65 78 65 } //1 \msnmsggr2.exe
		$a_01_2 = {5c 6a 61 76 61 68 75 6e 74 32 33 32 2e 65 78 65 } //1 \javahunt232.exe
		$a_01_3 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 UacDisableNotify
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}