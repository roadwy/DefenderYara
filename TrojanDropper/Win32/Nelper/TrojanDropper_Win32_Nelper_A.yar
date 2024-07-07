
rule TrojanDropper_Win32_Nelper_A{
	meta:
		description = "TrojanDropper:Win32/Nelper.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {83 e9 03 03 c1 c6 00 4c c6 40 01 4f c6 40 02 47 8d 85 8c fe ff ff 50 e8 a7 00 00 00 59 3b c6 59 89 45 f8 75 04 8b c7 eb 7b 50 57 ff 75 f4 ff 75 fc e8 } //1
		$a_01_1 = {8b 08 83 c0 04 83 a4 8d e8 fa ff ff 00 3d 50 50 40 00 72 ec 8d 45 e8 c7 45 e8 07 00 00 00 50 8d 45 f4 50 6a 00 8d 85 e8 fa ff ff 6a 00 50 6a 13 6a 13 } //1
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 2e 65 78 65 } //1 Download.exe
		$a_01_3 = {54 00 46 00 52 00 4d 00 50 00 52 00 4f 00 58 00 59 00 } //1 TFRMPROXY
		$a_01_4 = {54 00 46 00 52 00 4d 00 44 00 4f 00 57 00 4e 00 4c 00 4f 00 41 00 44 00 } //1 TFRMDOWNLOAD
		$a_01_5 = {75 72 6c 31 39 3a 68 74 74 70 3a 2f 2f 62 62 73 2e 63 6e 78 70 2e 63 6f 6d 31 39 3a 70 75 62 6c 69 73 68 65 72 2d 75 72 6c 2e 75 74 66 2d 38 31 39 3a 68 74 74 70 3a 2f 2f 62 62 73 2e 63 6e 78 70 2e 63 6f 6d 31 35 3a 70 75 62 6c 69 73 68 65 72 2e 75 74 66 2d 38 31 32 3a } //1 url19:http://bbs.cnxp.com19:publisher-url.utf-819:http://bbs.cnxp.com15:publisher.utf-812:
		$a_01_6 = {28 77 77 77 2e 35 32 62 74 2e 6e 65 74 29 2e 75 72 6c 65 65 65 34 3a 6e 61 6d 65 34 36 3a 5b 32 30 30 34 2e 30 39 2e 30 37 5d } //1 (www.52bt.net).urleee4:name46:[2004.09.07]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}