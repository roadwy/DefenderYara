
rule TrojanDownloader_Win32_Banload_ALD{
	meta:
		description = "TrojanDownloader:Win32/Banload.ALD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 90 02 10 68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f 90 02 08 2f 6d 6f 64 75 6c 6f 61 2e 6a 70 67 90 02 10 6d 66 72 73 90 02 04 2e 65 78 65 90 00 } //1
		$a_02_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 90 02 04 49 00 6e 00 73 00 74 00 61 00 6c 00 61 00 64 00 6f 00 72 00 2e 00 65 00 78 00 65 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}