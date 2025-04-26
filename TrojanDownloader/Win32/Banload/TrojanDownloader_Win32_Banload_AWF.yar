
rule TrojanDownloader_Win32_Banload_AWF{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWF,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 72 69 76 38 2e 67 6f 6f 67 6c 65 63 6f 64 65 2e 63 6f 6d 2f 73 76 6e 2f 52 75 6e 61 73 2e 65 78 65 00 } //1
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 52 75 6e 61 73 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}