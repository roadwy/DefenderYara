
rule TrojanDownloader_Win32_Castpon_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Castpon.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4c 24 04 8b c1 83 f1 fe 35 f0 00 00 00 83 e1 0f 25 f0 0f 00 00 c1 e0 04 c1 f8 08 c1 e1 04 0b c1 c3 0f b6 4c 24 04 8b c1 83 e0 0f c1 e0 04 c1 e9 04 0b c1 35 fe 00 00 00 c3 } //2
		$a_03_1 = {57 33 ff 39 7c 24 0c 7e 1c 56 8b 44 24 0c 8d 34 07 8a 04 07 50 e8 ?? ?? ?? ?? 47 59 3b 7c 24 10 88 06 7c e6 5e } //1
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {2d 64 65 6c 65 74 65 3d 00 00 00 2d 69 20 2d 61 64 64 3d 00 00 00 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}