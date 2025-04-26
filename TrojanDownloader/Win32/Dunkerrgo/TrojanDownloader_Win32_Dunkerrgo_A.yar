
rule TrojanDownloader_Win32_Dunkerrgo_A{
	meta:
		description = "TrojanDownloader:Win32/Dunkerrgo.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 fd 9a 80 5c 49 6e 65 74 4c 6f 61 64 2e 64 6c 6c 00 fe 1a 23 5c 69 6e 73 74 61 6c 6c 5f } //1
		$a_01_1 = {74 79 70 65 32 5f 74 2e 65 78 65 00 68 74 74 70 3a 2f 2f 64 6f 77 6e 2e 69 6e 70 72 69 76 61 63 79 2e 63 6f 2e 6b 72 2f 70 61 72 74 6e 65 72 } //1
		$a_01_2 = {77 2e 6a 6a 61 6e 66 69 6c 65 2e 63 6f 2e 6b 72 2f 63 6f 75 6e 74 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 3f 70 69 64 3d 77 69 6e 74 72 61 72 6f 61 } //1 w.jjanfile.co.kr/count/install.php?pid=wintraroa
		$a_01_3 = {6d 6d 6f 6e 20 46 69 6c 65 73 00 31 00 fe a2 31 5c 77 69 6e 74 72 61 72 6f 61 64 5c 77 69 6e 74 72 61 72 6f 61 64 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}