
rule TrojanDownloader_Win32_Renos_DD{
	meta:
		description = "TrojanDownloader:Win32/Renos.DD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7e 1f 56 8b f0 8d 55 0c 83 c2 04 8b 0a 85 c9 7c 06 32 4d 08 88 0e 46 ff 4d 0c 83 7d 0c 00 7f e8 5e } //1
		$a_01_1 = {74 1a 8b 45 0c 8b 00 33 ff 39 1e 76 0b 8a 4d fe 30 08 40 47 3b 3e 72 f5 } //1
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 6f 66 74 77 61 72 65 20 4e 6f 74 69 66 69 65 72 00 } //2
		$a_00_3 = {49 6e 73 74 61 6c 6c 61 74 69 6f 6e 49 44 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1) >=4
 
}