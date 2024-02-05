
rule TrojanSpy_Win32_Bancos_NE{
	meta:
		description = "TrojanSpy:Win32/Bancos.NE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {97 8b 8b 8f c5 d0 d0 94 97 9e 92 9a 91 9a 96 d1 9c 90 98 96 9e d1 91 9a 8b d0 86 d1 8f 97 8f } //01 00 
		$a_01_1 = {bb 01 00 00 00 8b c5 e8 1e 2a f9 ff 0f b6 54 1f ff f6 d2 88 54 18 ff 43 4e 75 ea } //00 00 
	condition:
		any of ($a_*)
 
}