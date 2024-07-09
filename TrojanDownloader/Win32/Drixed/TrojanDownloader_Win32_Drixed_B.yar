
rule TrojanDownloader_Win32_Drixed_B{
	meta:
		description = "TrojanDownloader:Win32/Drixed.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 5c 03 10 81 3b ef be ad de 74 } //1
		$a_01_1 = {65 64 67 00 2e 74 6d 70 00 00 00 00 2e 65 78 65 } //1
		$a_01_2 = {00 2e 73 64 61 74 61 00 00 20 00 00 00 2e 4b 42 00 44 69 73 70 6c 61 79 4e 61 6d 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Drixed_B_2{
	meta:
		description = "TrojanDownloader:Win32/Drixed.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2e 73 64 61 74 61 00 00 20 00 00 00 3f 00 00 00 2e 4b 42 00 44 69 73 70 6c 61 79 4e 61 6d 65 90 09 04 00 5f 00 00 00 } //1
		$a_03_1 = {81 3b ef be ad de 74 ?? eb } //1
		$a_01_2 = {c7 40 08 f7 28 9e 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}