
rule TrojanDownloader_Win32_Banload_ABW{
	meta:
		description = "TrojanDownloader:Win32/Banload.ABW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5a 3a 5c 50 72 6f 6a 65 74 6f 73 5c 6e 65 77 68 6f 70 65 5c 63 66 67 5c 76 64 62 5c 6c 69 62 5c 56 44 42 5f } //1 Z:\Projetos\newhope\cfg\vdb\lib\VDB_
		$a_01_1 = {e8 61 a1 fe ff 8b f0 8b 7d fc 85 ff 74 05 83 ef 04 8b 3f 8b 45 fc e8 c7 b3 fe ff 8b d0 8b cf 8b 45 f0 8b 38 ff 57 10 6a 00 6a 00 8b 45 f0 e8 73 97 ff ff 80 7d f7 00 74 25 6a 01 8b 4d f8 8b d6 8b 45 f0 e8 9e f9 ff ff 6a 00 6a 00 8b c6 e8 53 97 ff ff 8b d3 8b c6 e8 e6 fd ff ff eb 23 8b d6 8b 45 f0 e8 36 fc ff ff 6a 00 6a 00 8b c6 e8 33 97 ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}