
rule TrojanDownloader_Win32_Banload_ACM{
	meta:
		description = "TrojanDownloader:Win32/Banload.ACM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {68 75 61 6c 64 6f 2e 65 78 65 [0-10] 63 3a 5c 57 69 6e 64 6f 77 73 5c 49 6e 73 74 61 6c 6c 4d 53 4e 2e 65 78 65 } //1
		$a_01_1 = {56 4f 58 43 41 52 44 53 20 2d 20 56 69 73 75 61 6c 69 7a 61 72 } //1 VOXCARDS - Visualizar
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}