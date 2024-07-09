
rule TrojanSpy_Win32_Bancos_NL{
	meta:
		description = "TrojanSpy:Win32/Bancos.NL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b d0 f6 d2 80 f2 ?? 8d 45 f0 e8 ?? ?? ?? ?? 8b 55 f0 8b c6 e8 ?? ?? ?? ?? 8d 45 fc e8 ?? ?? ?? ?? fe 45 fb fe cb 75 93 } //2
		$a_01_1 = {42 72 61 64 65 73 63 6f } //1 Bradesco
		$a_03_2 = {73 65 6e 68 61 (3d|20) } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}