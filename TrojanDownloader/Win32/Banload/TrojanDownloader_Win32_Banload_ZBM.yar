
rule TrojanDownloader_Win32_Banload_ZBM{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZBM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 8b c3 e8 ?? ?? 00 00 3c 01 75 53 33 d2 8b 83 f0 02 00 00 e8 ?? ?? ?? ff b8 ?? ?? 45 00 e8 ?? ?? ?? ff 84 c0 75 38 ba ?? ?? 45 00 b8 ?? ?? 45 00 e8 ?? ?? ff ff 6a 01 68 ?? ?? 45 00 e8 ?? ?? ?? ff 68 dc 05 00 00 e8 ?? ?? ?? ff a1 ?? ?? 45 00 8b 00 e8 ?? ?? ff ff eb 05 } //1
		$a_02_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e [0-10] 52 75 6e [0-10] 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 [0-20] 2e 65 78 65 [0-10] 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e [0-25] 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 66 69 72 65 77 61 6c 6c 2e 63 70 6c [0-23] 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 5c [0-10] 2e 65 78 65 [0-10] 43 3a 5c 57 69 6e 64 6f 77 73 5c [0-10] 2e 65 78 65 [0-12] 2a 3a 45 6e 61 62 6c 65 64 3a [0-10] 2e 65 78 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}