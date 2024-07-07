
rule TrojanDownloader_Win32_Nuphusino_A{
	meta:
		description = "TrojanDownloader:Win32/Nuphusino.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 75 73 65 72 4e 61 6d 65 3d 25 73 26 63 6f 6d 70 4e 61 6d 65 3d 25 73 00 } //1
		$a_01_1 = {2f 73 6f 70 68 69 61 2f 69 6e 66 6f 33 32 2e 70 68 70 00 } //1
		$a_01_2 = {73 6f 70 68 69 61 5c 53 6f 70 68 69 61 5c 53 6f 70 68 69 61 5c 52 65 6c 65 61 73 65 5c 53 6f 70 68 69 61 2e 70 64 62 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}