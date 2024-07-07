
rule TrojanDownloader_Win32_Delf_UH{
	meta:
		description = "TrojanDownloader:Win32/Delf.UH,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 75 e0 68 d4 3a 47 00 8d 45 f8 ba 04 00 00 00 e8 af 0b f9 ff 8b 45 f4 e8 8f 51 f9 ff 84 c0 74 08 8b 45 f4 e8 a7 51 f9 ff 8d 45 fc ba f8 3a 47 00 e8 a6 08 f9 ff 8b 45 f8 e8 6e 51 f9 ff 84 c0 75 3b 8d 55 dc 8b 45 fc e8 ef fd ff ff 8b 55 dc 8d 45 fc e8 84 08 f9 ff 83 7d fc 00 74 1f 6a 00 6a 00 8b 45 f8 e8 9a 0c f9 ff 50 8b 45 fc e8 91 0c f9 ff 50 6a 00 e8 3d 84 fb ff 85 c0 } //1
		$a_01_1 = {68 74 74 70 3a 2f 2f 63 61 73 68 62 61 63 6b 2e 6a 2d 6e 61 76 65 72 32 2e 63 6f 6d 2f 65 78 65 2f 75 72 6c 32 2e 68 74 6d 6c 00 00 6f 70 65 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}