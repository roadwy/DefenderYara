
rule TrojanDownloader_Win32_Stration_AS{
	meta:
		description = "TrojanDownloader:Win32/Stration.AS,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 62 74 63 68 65 63 6b 2e 65 78 65 20 48 54 54 50 2f 31 2e 31 } //1 GET /btcheck.exe HTTP/1.1
		$a_01_1 = {47 45 54 20 2f 77 69 6e 63 68 33 32 2e 65 78 65 20 48 54 54 50 2f 31 2e 31 } //1 GET /winch32.exe HTTP/1.1
		$a_03_2 = {68 74 74 70 3a 2f 2f 74 72 79 2d 61 6e 79 74 68 69 6e 67 2d 65 6c 73 65 2e 63 6f 6d 2f [0-0a] 2e 65 78 65 } //10
		$a_11_3 = {6f 73 74 3a 20 74 72 79 2d 61 6e 79 74 68 69 6e 67 2d 65 6c 73 65 2e 63 6f 6d 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*10+(#a_11_3  & 1)*10) >=20
 
}