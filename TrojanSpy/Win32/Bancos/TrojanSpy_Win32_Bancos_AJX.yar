
rule TrojanSpy_Win32_Bancos_AJX{
	meta:
		description = "TrojanSpy:Win32/Bancos.AJX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 44 61 64 6f 73 20 64 65 20 61 70 6c 69 63 61 74 69 76 6f 73 5c 6c 69 62 6d 79 73 71 6c 2e 64 6c 6c } //1 \Dados de aplicativos\libmysql.dll
		$a_02_1 = {2e 67 69 66 00 90 05 03 01 00 ff ff ff ff 0b 00 00 00 75 73 65 72 70 72 6f 66 69 6c 65 } //1
		$a_03_2 = {8d 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 fc b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 55 f8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 f8 b8 ?? ?? ?? ?? b9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}