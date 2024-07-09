
rule TrojanDownloader_BAT_Gendwnurl_BM_bit{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.BM!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 } //1 C:\Windows\Temp\
		$a_03_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 6f 00 6e 00 65 00 63 00 6f 00 6d 00 2e 00 64 00 64 00 6e 00 73 00 2e 00 6e 00 65 00 74 00 [0-10] 2e 00 7a 00 69 00 70 00 } //1
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 5c 00 52 00 75 00 6e 00 } //1 Software\\Microsoft\\Windows\\CurrentVersion\\Run
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}