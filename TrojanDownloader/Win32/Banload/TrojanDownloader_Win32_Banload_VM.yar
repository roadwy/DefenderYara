
rule TrojanDownloader_Win32_Banload_VM{
	meta:
		description = "TrojanDownloader:Win32/Banload.VM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 74 2d 63 61 6e 65 74 65 2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f 74 69 67 72 61 6f 2e 6a 70 67 00 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 4a 61 76 61 73 73 39 31 2e 65 78 65 } //1
		$a_01_1 = {6d 74 2d 63 61 6e 65 74 65 2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f 73 65 63 64 65 6d 6f 2e 6a 70 67 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 4a 61 76 61 73 73 39 32 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}