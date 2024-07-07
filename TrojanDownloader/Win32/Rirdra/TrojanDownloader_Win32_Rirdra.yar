
rule TrojanDownloader_Win32_Rirdra{
	meta:
		description = "TrojanDownloader:Win32/Rirdra,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 31 31 35 2e 32 38 2e 33 32 2e 31 32 00 } //1
		$a_01_1 = {47 45 54 20 2f 37 2f 3f 72 3d 73 69 74 65 2f 47 54 43 44 20 48 54 54 50 2f 31 2e 30 0d 0a 48 6f 73 74 3a 20 31 31 35 2e 32 38 2e 33 32 2e 31 32 0d 0a } //1
		$a_01_2 = {53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 41 } //1 SHGetFolderPathA
		$a_01_3 = {55 6e 69 6e 69 74 69 61 6c 69 7a 65 43 6f 6d } //1 UninitializeCom
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}