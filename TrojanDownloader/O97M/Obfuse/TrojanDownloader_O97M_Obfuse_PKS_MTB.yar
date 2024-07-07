
rule TrojanDownloader_O97M_Obfuse_PKS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PKS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 22 } //1 = "://www.bitly.com/"
		$a_01_1 = {2e 63 6f 70 79 66 69 6c 65 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6d 73 68 74 61 2e 65 78 65 22 2c 20 45 6e 76 69 72 6f 6e 28 22 50 55 42 4c 49 43 22 29 20 26 20 22 5c 70 65 65 65 2e 63 6f 6d 22 2c 20 54 72 75 65 } //1 .copyfile "C:\Windows\System32\mshta.exe", Environ("PUBLIC") & "\peee.com", True
		$a_01_2 = {22 45 52 52 4f 52 20 21 21 21 22 3a 20 43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 20 5f } //1 "ERROR !!!": Call VBA.Shell _
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}