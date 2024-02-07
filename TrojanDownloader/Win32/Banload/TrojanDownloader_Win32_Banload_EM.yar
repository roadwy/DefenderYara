
rule TrojanDownloader_Win32_Banload_EM{
	meta:
		description = "TrojanDownloader:Win32/Banload.EM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c0 ba 18 ca 44 00 b8 40 ca 44 00 e8 51 ff ff ff 84 c0 74 0c 6a 00 68 88 ca 44 00 e8 ad 95 fb ff 68 c4 09 00 00 e8 1f fa fb ff ba b0 ca 44 00 b8 d8 ca 44 00 e8 28 ff ff ff 84 c0 74 0c 6a 00 68 20 cb 44 00 e8 84 95 fb ff 6a 00 68 88 ca 44 00 e8 78 95 fb ff e8 13 73 fb ff } //01 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 69 64 72 65 61 6d 6b 69 64 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 74 65 63 68 6e 6f 74 65 2f 62 6f 61 72 64 2f 73 68 6f 70 6b 65 65 70 65 72 32 2f 6d 65 6d 62 65 72 2f 6b 31 2e 67 69 66 } //01 00  http://idreamkid.com/cgi-bin/technote/board/shopkeeper2/member/k1.gif
		$a_00_2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 63 6f 6d 61 6e 64 73 32 2e 65 78 65 } //01 00  c:\windows\system\comands2.exe
		$a_00_3 = {68 74 74 70 3a 2f 2f 69 64 72 65 61 6d 6b 69 64 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 74 65 63 68 6e 6f 74 65 2f 62 6f 61 72 64 2f 73 68 6f 70 6b 65 65 70 65 72 32 2f 6d 65 6d 62 65 72 2f 6b 32 2e 67 69 66 } //00 00  http://idreamkid.com/cgi-bin/technote/board/shopkeeper2/member/k2.gif
	condition:
		any of ($a_*)
 
}