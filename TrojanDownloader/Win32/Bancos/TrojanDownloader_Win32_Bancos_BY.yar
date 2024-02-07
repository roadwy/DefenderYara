
rule TrojanDownloader_Win32_Bancos_BY{
	meta:
		description = "TrojanDownloader:Win32/Bancos.BY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 65 72 69 61 73 63 61 6e 63 75 6e 2e 68 70 67 2e 63 6f 6d 2e 62 72 2f 74 75 74 6f 2e 68 74 6d 6c } //01 00  feriascancun.hpg.com.br/tuto.html
		$a_01_1 = {61 74 74 72 69 62 20 2b 72 20 2b 73 20 2b 68 20 43 3a 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  attrib +r +s +h C:\svchost.exe
		$a_01_2 = {89 74 24 04 8d 95 64 ff ff ff b8 64 00 00 00 89 54 24 0c 89 44 24 08 89 3c 24 e8 } //00 00 
	condition:
		any of ($a_*)
 
}