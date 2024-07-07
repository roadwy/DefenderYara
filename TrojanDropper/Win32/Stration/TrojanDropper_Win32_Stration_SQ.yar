
rule TrojanDropper_Win32_Stration_SQ{
	meta:
		description = "TrojanDropper:Win32/Stration.SQ,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_00_0 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31 } //10 GET %s HTTP/1.1
		$a_00_1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 29 } //10 User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
		$a_00_2 = {41 63 63 65 70 74 2d 45 6e 63 6f 64 69 6e 67 3a 20 67 7a 69 70 2c 20 64 65 66 6c 61 74 65 } //10 Accept-Encoding: gzip, deflate
		$a_02_3 = {74 72 79 2d 61 6e 79 74 68 69 6e 67 2d 65 6c 73 65 2e 63 6f 6d 2f 90 02 0a 2e 65 78 65 90 00 } //1
		$a_02_4 = {6c 6f 63 61 6c 68 6f 73 74 2d 32 2e 63 6f 6d 2f 90 02 0a 2e 65 78 65 90 00 } //1
		$a_02_5 = {72 78 2d 66 72 6f 6d 2d 77 61 72 65 68 6f 75 73 65 33 2e 63 6f 6d 2f 90 02 0a 2e 65 78 65 90 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=31
 
}