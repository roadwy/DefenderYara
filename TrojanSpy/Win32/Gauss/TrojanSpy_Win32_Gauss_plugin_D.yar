
rule TrojanSpy_Win32_Gauss_plugin_D{
	meta:
		description = "TrojanSpy:Win32/Gauss.plugin!D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 44 24 14 89 44 24 18 89 44 24 1c 89 44 24 20 89 44 24 24 8d 44 24 08 50 68 01 00 00 80 8d 4c 24 18 51 6a 00 c7 44 24 18 00 00 00 00 c7 44 24 20 00 00 00 00 e8 ?? ?? ?? ?? 85 c0 74 0b 50 e8 } //1
		$a_02_1 = {83 78 18 08 56 57 8b f9 72 05 8b 40 04 eb 03 83 c0 04 6a 00 6a 00 6a 02 6a 00 6a 05 68 00 00 00 40 50 ff 15 ?? ?? ?? ?? 8b f0 83 fe ff 75 0a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}