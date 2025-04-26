
rule TrojanDownloader_Win32_Blocrypt_B_bit{
	meta:
		description = "TrojanDownloader:Win32/Blocrypt.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 42 00 61 00 73 00 65 00 42 00 6f 00 61 00 72 00 64 00 } //1 SELECT * FROM Win32_BaseBoard
		$a_01_1 = {76 76 79 6f 6d 6d } //1 vvyomm
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 41 00 64 00 56 00 50 00 4e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Uninstall\AdVPN
		$a_03_3 = {8b c1 33 d2 f7 35 ?? ?? ?? ?? 41 8a 82 ?? ?? ?? ?? 2a 44 0b ff 88 44 0b ff 3b 4d 0c 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}