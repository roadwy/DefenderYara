
rule TrojanDownloader_Win32_Gonolitz_A{
	meta:
		description = "TrojanDownloader:Win32/Gonolitz.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 63 65 20 73 75 72 76 65 79 20 69 73 20 63 6f 6d 70 6c 65 74 65 64 } //1 Once survey is completed
		$a_01_1 = {46 69 6c 65 2e 72 61 72 } //1 File.rar
		$a_01_2 = {6f 6c 69 67 6f 6e 20 64 6f 77 6e 6c 6f 61 64 65 72 } //1 oligon downloader
		$a_01_3 = {66 00 72 00 65 00 65 00 62 00 65 00 73 00 74 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 69 00 6d 00 65 00 2e 00 68 00 74 00 6d 00 } //1 freebests.com/time.htm
		$a_01_4 = {62 00 65 00 73 00 74 00 6c 00 69 00 6e 00 6b 00 66 00 72 00 65 00 65 00 2e 00 63 00 6f 00 6d 00 } //1 bestlinkfree.com
		$a_01_5 = {62 00 6e 00 5c 00 42 00 75 00 72 00 65 00 61 00 75 00 } //1 bn\Bureau
		$a_01_6 = {68 00 74 00 6d 00 6c 00 32 00 66 00 70 00 64 00 66 00 2f 00 66 00 6f 00 6e 00 74 00 2f 00 6d 00 61 00 6b 00 65 00 66 00 6f 00 6e 00 74 00 2f 00 66 00 69 00 6c 00 65 00 73 00 } //1 html2fpdf/font/makefont/files
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}