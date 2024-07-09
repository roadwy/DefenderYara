
rule TrojanDownloader_Win32_Trosup_A{
	meta:
		description = "TrojanDownloader:Win32/Trosup.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a c2 b1 03 f6 e9 ?? ?? ?? ?? 00 04 32 83 c9 ff 33 c0 42 f2 ae f7 d1 49 3b d1 72 ?? 80 24 32 00 5f 5e c3 } //10
		$a_02_1 = {c9 c3 56 be ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? c7 04 24 4d 01 00 00 56 e8 ?? ?? ?? ?? 59 59 5e c3 } //10
		$a_02_2 = {25 73 25 64 [0-08] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 00 75 72 6c 6d 6f 6e 2e 64 6c 6c [0-10] 25 64 00 00 5c 55 73 70 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*1) >=21
 
}