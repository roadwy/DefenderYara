
rule TrojanDownloader_Win32_Wafake_A{
	meta:
		description = "TrojanDownloader:Win32/Wafake.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 75 08 6a 01 e8 ?? ?? 01 00 83 c4 04 8d 4d 0c 51 6a 00 56 50 e8 72 ff ff ff ff 70 04 ff 30 e8 } //1
		$a_01_1 = {55 8b ec 51 33 c0 88 45 ff 8b e5 5d c3 cc cc cc 55 8b ec 51 33 c0 88 45 ff 8b e5 5d c3 cc cc cc 55 8b ec 51 33 c0 88 45 ff 8b e5 5d c3 } //1
		$a_01_2 = {4f 00 6c 00 65 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 4f 00 6c 00 65 00 41 00 75 00 74 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 53 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}