
rule TrojanDownloader_Win32_Daws_A{
	meta:
		description = "TrojanDownloader:Win32/Daws.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c1 e9 02 83 e2 03 83 f9 08 72 90 01 01 f3 a5 ff 24 95 90 02 04 8b c7 ba 03 00 00 00 83 e9 04 72 90 01 01 83 e0 03 03 c8 ff 24 85 90 00 } //1
		$a_80_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 6c 73 68 6f 73 74 2e 65 78 65 } //C:\Windows\lshost.exe  1
		$a_00_2 = {53 70 79 50 72 6f 6a 65 63 74 5c 52 65 6c 65 61 73 65 5c 4c 61 75 6e 63 68 65 72 2e 70 64 62 } //1 SpyProject\Release\Launcher.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}