
rule TrojanSpy_Win32_Bancos_gen_J{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {be 01 00 00 00 8b 45 ec 0f b6 7c 30 ff 8b 45 e0 0f b6 00 89 45 f4 8d 45 e4 8b d7 2b 55 f4 2b 55 f0 e8 ?? ?? ?? ?? 8d 45 e8 8b 55 e4 e8 ?? ?? ?? ?? 46 4b 75 } //1
		$a_03_1 = {8b 86 1c 03 00 00 e8 ?? ?? ?? ?? 48 84 c0 72 ?? 40 88 45 ff b3 00 8b fb 81 e7 ff 00 00 00 8b 86 1c 03 00 00 8b 04 b8 8b 00 8d 55 f8 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}