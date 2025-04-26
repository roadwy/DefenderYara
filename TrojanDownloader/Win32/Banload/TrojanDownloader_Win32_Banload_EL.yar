
rule TrojanDownloader_Win32_Banload_EL{
	meta:
		description = "TrojanDownloader:Win32/Banload.EL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 72 71 75 69 76 6f 20 63 6f 72 72 6f 6d 70 69 64 6f 00 00 ff ff ff ff 12 00 00 00 63 3a 5c 77 69 6e 64 6f 77 73 5c 78 70 31 2e 65 78 65 } //2
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 65 62 64 65 73 69 67 6e 2d 66 6f 78 2e 63 6f 6d 2f 62 6f 78 2f 50 72 69 76 38 5f 42 65 61 73 74 2e 65 78 65 00 00 00 00 63 3a 5c 77 69 6e 64 6f 77 73 5c 78 70 31 2e 65 78 65 } //2
		$a_01_2 = {55 52 4c 4d 4f 4e 2e 44 4c 4c 00 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}