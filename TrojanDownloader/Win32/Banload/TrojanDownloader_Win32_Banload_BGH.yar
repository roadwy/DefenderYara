
rule TrojanDownloader_Win32_Banload_BGH{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 73 79 73 74 65 6d 33 32 2e 65 78 65 } //1 \system32.exe
		$a_03_1 = {05 a8 00 00 00 ba 90 01 04 e8 39 f1 f6 ff 8b ce ba 90 01 04 8b 83 f8 02 00 00 e8 97 c0 ff ff 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}