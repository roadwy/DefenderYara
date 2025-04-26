
rule TrojanSpy_Win32_Bancos_SG{
	meta:
		description = "TrojanSpy:Win32/Bancos.SG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3b 3c 23 46 46 54 4a 57 29 5c 60 5e 4e 5a 2f 4a 4b 00 } //1 㰻䘣呆坊尩幠婎䨯K
		$a_01_1 = {48 74 78 74 74 26 5a 69 6f 7c 6c 2c 60 3c 50 3e 00 } //1
		$a_03_2 = {bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 81 ea 00 01 00 00 e8 ?? ?? ?? ?? 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ?? 43 4e 75 d9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}