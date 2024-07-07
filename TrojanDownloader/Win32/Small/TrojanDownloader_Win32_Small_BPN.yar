
rule TrojanDownloader_Win32_Small_BPN{
	meta:
		description = "TrojanDownloader:Win32/Small.BPN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 00 63 3a 5c 6d 75 6d 61 2e 65 78 65 00 63 3a 5c 31 32 33 2e 65 78 65 00 00 68 74 74 70 3a 2f } //1
		$a_01_1 = {74 6f 72 75 6e 2e 69 6e 66 00 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 3d 76 69 72 75 73 2e 65 78 65 00 00 00 00 5b 41 75 74 6f 52 75 6e 5d 00 00 00 5c 76 69 72 75 73 2e 65 78 65 } //1
		$a_01_2 = {72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 5c 75 73 62 76 69 72 75 73 2e 65 78 65 00 00 00 54 65 73 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}