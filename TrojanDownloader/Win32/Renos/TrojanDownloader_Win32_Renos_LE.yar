
rule TrojanDownloader_Win32_Renos_LE{
	meta:
		description = "TrojanDownloader:Win32/Renos.LE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {3c 63 6f 6e 66 69 67 3e 3c 75 72 6c 3e 68 74 74 70 3a 2f 2f ?? ?? ?? ?? [0-20] 2f 72 65 73 6f 6c 75 74 69 6f 6e 2e 70 68 70 3c 2f 75 72 6c 3e } //2
		$a_03_1 = {3c 67 65 74 68 69 74 3e 3c 75 72 6c 3e 68 74 74 70 3a 2f 2f ?? ?? ?? ?? [0-20] 2f 62 6f 72 64 65 72 73 2e 70 68 70 3c 2f 75 72 6c 3e } //2
		$a_01_2 = {3c 75 72 6c 20 63 72 79 70 74 3d 22 6f 6e 22 3e 68 74 74 70 3a 2f 2f } //1 <url crypt="on">http://
		$a_03_3 = {3c 63 6f 6e 66 69 67 3e 3c 75 72 6c 20 70 6f 73 74 3d 22 6f 6e 22 3e 68 74 74 70 3a 2f 2f ?? ?? ?? ?? [0-20] 2f 61 64 5f 74 79 70 65 2e 70 68 70 3c 2f 75 72 6c 3e } //2
		$a_01_4 = {3c 75 72 6c 20 63 72 79 70 74 3d 22 6f 6e 22 20 70 6f 73 74 3d 22 6f 6e 22 3e 68 74 74 70 3a 2f 2f } //1 <url crypt="on" post="on">http://
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1) >=3
 
}