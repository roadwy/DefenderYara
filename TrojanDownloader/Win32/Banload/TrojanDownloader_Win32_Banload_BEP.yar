
rule TrojanDownloader_Win32_Banload_BEP{
	meta:
		description = "TrojanDownloader:Win32/Banload.BEP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 44 50 fe 33 45 e0 89 45 dc 8b 45 dc 3b 45 ec 7f 10 } //1
		$a_01_1 = {3a 31 0d 0a 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 0d 0a 45 72 61 73 65 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22 0d 0a 49 66 20 65 78 69 73 74 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22 20 47 6f 74 6f 20 31 0d 0a 45 72 61 73 65 20 22 43 3a 5c 6d 79 61 70 70 2e 62 61 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}