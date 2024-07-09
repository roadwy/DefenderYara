
rule TrojanDownloader_Win32_Bancos_DM{
	meta:
		description = "TrojanDownloader:Win32/Bancos.DM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a 00 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 f8 ba 02 00 00 00 e8 } //1
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 6f 74 6f 73 76 63 75 6f 6c 6b 2e 63 6f 6d 2f 31 2e 6a 70 67 00 } //1
		$a_01_2 = {5c 41 72 71 75 69 76 6f 73 20 63 6f 6d 75 6e 73 5c 6b 6c 73 79 73 2e 65 78 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}