
rule TrojanDownloader_Win32_Syten_A{
	meta:
		description = "TrojanDownloader:Win32/Syten.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {c6 45 e0 4d c6 45 e1 6f c6 45 e2 7a c6 45 e3 69 c6 45 e4 6c c6 45 e5 6c c6 45 e6 61 } //02 00 
		$a_03_1 = {8b 5c 24 18 66 81 3b 4d 5a 0f 85 90 01 03 55 ff d6 8b 7b 3c 03 fb 81 3f 50 45 00 00 0f 85 90 01 04 55 90 00 } //03 00 
		$a_00_2 = {c6 45 f5 41 c6 45 f6 70 c6 45 f7 70 c6 45 f8 50 c6 45 f9 61 c6 45 fa 74 c6 45 fb 63 c6 45 fc 68 } //05 00 
		$a_01_3 = {68 74 74 70 3a 2f 2f 36 31 2e 31 36 30 2e 32 32 32 2e 31 31 3a } //05 00  http://61.160.222.11:
		$a_01_4 = {74 62 79 39 79 4d 47 36 37 4f 33 76 41 61 6e 49 76 71 38 42 76 72 37 66 38 4f 33 75 36 2b 7a 70 36 76 66 66 2b 4f 2f 34 37 39 2f 34 37 2f 6a 76 33 2b 76 73 36 2b 6e 74 39 2f 6a 33 36 69 55 58 64 6e 73 4d 45 74 2b 4c 38 4f 7a 76 36 65 33 } //00 00  tby9yMG67O3vAanIvq8Bvr7f8O3u6+zp6vff+O/479/47/jv3+vs6+nt9/j36iUXdnsMEt+L8Ozv6e3
		$a_00_5 = {5d 04 00 00 82 } //40 03 
	condition:
		any of ($a_*)
 
}