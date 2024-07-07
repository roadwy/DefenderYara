
rule TrojanDownloader_Win32_Gendwnurl_BL_bit{
	meta:
		description = "TrojanDownloader:Win32/Gendwnurl.BL!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 00 65 00 6e 00 73 00 65 00 2e 00 73 00 64 00 66 00 67 00 66 00 64 00 67 00 2e 00 70 00 77 00 } //1 sense.sdfgfdg.pw
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //1 URLDownloadToFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}