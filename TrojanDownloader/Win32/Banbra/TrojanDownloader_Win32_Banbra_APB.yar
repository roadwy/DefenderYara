
rule TrojanDownloader_Win32_Banbra_APB{
	meta:
		description = "TrojanDownloader:Win32/Banbra.APB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 6f 65 73 74 65 70 61 75 6c 69 73 74 61 2e 63 6f 6d 2e 62 72 2f 63 6f 72 65 6c 2f 70 68 70 2f 61 64 64 2e 70 68 70 00 } //1
		$a_03_1 = {43 3a 5c 67 6f 6f 67 6c 65 2e 74 78 74 90 02 0c 41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 90 00 } //1
		$a_03_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 90 02 09 66 69 6c 65 3a 2f 2f 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}