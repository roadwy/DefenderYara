
rule TrojanSpy_Win32_Bancos_AJX{
	meta:
		description = "TrojanSpy:Win32/Bancos.AJX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 44 61 64 6f 73 20 64 65 20 61 70 6c 69 63 61 74 69 76 6f 73 5c 6c 69 62 6d 79 73 71 6c 2e 64 6c 6c } //01 00  \Dados de aplicativos\libmysql.dll
		$a_02_1 = {2e 67 69 66 00 90 05 03 01 00 ff ff ff ff 0b 00 00 00 75 73 65 72 70 72 6f 66 69 6c 65 90 00 } //01 00 
		$a_03_2 = {8d 55 fc b8 90 01 04 e8 90 01 04 8b 55 fc b8 90 01 04 b9 90 01 04 e8 90 01 04 8d 55 f8 b8 90 01 04 e8 90 01 04 8b 55 f8 b8 90 01 04 b9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}