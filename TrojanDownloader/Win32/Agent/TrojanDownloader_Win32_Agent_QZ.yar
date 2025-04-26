
rule TrojanDownloader_Win32_Agent_QZ{
	meta:
		description = "TrojanDownloader:Win32/Agent.QZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 05 57 33 c9 56 8d 41 01 8d 95 fc fe ff ff c7 86 58 15 00 00 c8 00 00 00 } //1
		$a_01_1 = {68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 2f 64 6f 77 6e 2f 6c 69 73 74 32 2e 74 78 74 } //1 http://127.0.0.1/down/list2.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}