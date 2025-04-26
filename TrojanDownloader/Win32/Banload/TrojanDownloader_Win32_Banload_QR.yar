
rule TrojanDownloader_Win32_Banload_QR{
	meta:
		description = "TrojanDownloader:Win32/Banload.QR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f [0-0f] 2f 66 6f 74 6f 73 2e 6a 70 67 } //1
		$a_03_1 = {44 69 72 65 63 74 58 73 2e 65 78 65 [0-05] 43 3a 5c 77 69 6e 64 6f 77 73 5c 6d 73 6e 67 72 73 2e 65 78 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}