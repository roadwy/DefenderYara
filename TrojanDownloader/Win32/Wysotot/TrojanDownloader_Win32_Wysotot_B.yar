
rule TrojanDownloader_Win32_Wysotot_B{
	meta:
		description = "TrojanDownloader:Win32/Wysotot.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 0c 66 83 38 2d 74 12 83 c0 02 49 75 f4 5f 5b 83 c8 ff } //1
		$a_81_1 = {2f 65 47 64 70 53 76 63 2e 65 78 65 } //1 /eGdpSvc.exe
		$a_01_2 = {2d 00 75 00 72 00 6c 00 20 00 22 00 25 00 73 00 22 00 20 00 2d 00 66 00 20 00 22 00 25 00 73 00 22 00 20 00 2d 00 65 00 78 00 65 00 20 00 22 00 25 00 73 00 22 00 20 00 2d 00 68 00 69 00 64 00 65 00 20 00 2d 00 75 00 69 00 64 00 20 00 25 00 64 00 } //1 -url "%s" -f "%s" -exe "%s" -hide -uid %d
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}