
rule TrojanDownloader_Win32_Joulwo_A{
	meta:
		description = "TrojanDownloader:Win32/Joulwo.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {53 68 00 00 00 02 6a 03 53 6a 01 68 00 00 00 80 50 ff 15 ?? ?? ?? 10 6a 02 8b f8 53 68 38 ff ff ff 57 ff 15 ?? ?? ?? 10 8d 45 e8 53 50 8d 85 d8 fe ff ff 68 c8 00 00 00 50 57 } //3
		$a_03_1 = {68 98 3a 00 00 56 6a 02 e8 ?? ?? ff ff 85 c0 56 74 ?? 68 00 01 00 00 ff 15 } //2
		$a_03_2 = {68 00 28 00 00 50 ff 74 24 38 ff 15 ?? ?? ?? 10 83 f8 01 0f 85 ?? ?? ?? 00 bd 70 5a 00 10 55 e8 ?? ?? ?? 00 59 b9 fb 27 00 00 2b } //3
		$a_01_3 = {5b 50 61 73 73 77 6f 72 64 5d } //1 [Password]
		$a_01_4 = {5b 42 61 63 6b 75 70 5d } //1 [Backup]
		$a_01_5 = {5b 73 65 72 76 65 72 31 5d } //1 [server1]
		$a_01_6 = {5b 50 72 69 6d 61 72 79 5d } //1 [Primary]
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_03_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}