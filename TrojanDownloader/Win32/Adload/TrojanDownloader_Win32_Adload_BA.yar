
rule TrojanDownloader_Win32_Adload_BA{
	meta:
		description = "TrojanDownloader:Win32/Adload.BA,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 6c 78 75 } //1 http://www.alxu
		$a_01_1 = {69 63 65 50 72 6f 63 65 73 73 00 00 4b 45 52 4e 45 4c 33 32 00 00 00 00 5c 41 64 73 4e 54 2e 65 78 65 00 00 41 64 73 4e 54 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}