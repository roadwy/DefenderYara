
rule Worm_Win32_Dedler_AE{
	meta:
		description = "Worm:Win32/Dedler.AE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {8d 44 24 00 53 56 8b 35 ?? ?? ?? ?? 57 6a 14 50 68 ?? ?? ?? ?? ff d6 8d 4c 24 20 68 ff 00 00 00 51 68 ?? ?? ?? ?? ff d6 83 c9 ff 8d 7c 24 0c 33 c0 8b 94 24 24 01 00 00 f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 } //1
		$a_00_1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 29 } //1 User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
		$a_00_2 = {6c 6f 67 69 6e 2e 69 63 71 2e 63 6f 6d } //1 login.icq.com
		$a_00_3 = {25 73 61 75 74 6f 2e 70 68 70 3f 76 3d 25 64 } //1 %sauto.php?v=%d
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}