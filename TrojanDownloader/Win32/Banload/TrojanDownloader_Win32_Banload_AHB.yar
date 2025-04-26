
rule TrojanDownloader_Win32_Banload_AHB{
	meta:
		description = "TrojanDownloader:Win32/Banload.AHB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2e 63 6f 6d 2e 62 72 2f 61 74 6d 70 2e 7a 69 70 00 [0-10] 68 74 74 70 3a 2f 2f } //1
		$a_01_1 = {2e 65 78 65 00 41 64 6f 62 65 20 52 65 61 64 65 72 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}