
rule TrojanDownloader_Win32_Zegter_SK_MTB{
	meta:
		description = "TrojanDownloader:Win32/Zegter.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 34 37 2e 39 33 2e 36 30 2e 36 33 3a 38 30 30 30 2f 65 78 70 6c 6f 72 6f 72 2e 65 78 65 } //1 http://47.93.60.63:8000/exploror.exe
		$a_01_1 = {43 3a 5c 77 69 6e 64 6f 77 73 73 36 34 5c 63 6f 6d 70 75 74 65 72 2e 65 78 65 } //1 C:\windowss64\computer.exe
		$a_01_2 = {6d 64 20 43 3a 5c 77 69 6e 64 6f 77 73 73 36 34 } //1 md C:\windowss64
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}