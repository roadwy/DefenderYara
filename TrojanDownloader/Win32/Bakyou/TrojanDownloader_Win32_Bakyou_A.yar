
rule TrojanDownloader_Win32_Bakyou_A{
	meta:
		description = "TrojanDownloader:Win32/Bakyou.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 70 72 6f 6a 65 63 74 5c 4f 6e 6c 69 6e 65 53 65 74 75 70 5c 4f 6e 6c 69 6e 65 53 65 74 75 70 5c 52 65 6c 65 61 73 65 5c 59 6f 75 62 61 6b 69 6e 73 74 61 6c 6c 65 72 } //1 \project\OnlineSetup\OnlineSetup\Release\Youbakinstaller
		$a_03_1 = {5c 4a 6a 6c 44 6f 77 6e 4c 6f 61 64 65 72 90 02 1a 43 6c 6f 75 64 45 78 5f 6f 6e 6c 69 6e 65 73 65 74 75 70 2e 65 78 65 90 00 } //1
		$a_01_2 = {50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 } //1 PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDING
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}