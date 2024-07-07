
rule TrojanDownloader_Win32_Bancos_CL{
	meta:
		description = "TrojanDownloader:Win32/Bancos.CL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 71 6d 64 61 74 30 90 01 01 2e 65 78 65 90 00 } //1
		$a_03_1 = {7e 73 79 73 74 65 6d 2f 63 6f 72 70 6f 2f 90 02 08 2e 67 69 66 90 00 } //1
		$a_01_2 = {2d 20 56 69 73 75 61 6c 69 7a 61 64 6f 72 20 64 65 20 69 6d 61 67 65 6e 73 20 65 20 66 61 78 20 64 6f 20 57 69 6e 64 6f 77 73 2e 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}