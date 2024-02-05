
rule TrojanSpy_Win32_Bancos_NL{
	meta:
		description = "TrojanSpy:Win32/Bancos.NL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b d0 f6 d2 80 f2 90 01 01 8d 45 f0 e8 90 01 04 8b 55 f0 8b c6 e8 90 01 04 8d 45 fc e8 90 01 04 fe 45 fb fe cb 75 93 90 00 } //01 00 
		$a_01_1 = {42 72 61 64 65 73 63 6f } //01 00 
		$a_03_2 = {73 65 6e 68 61 90 03 01 01 3d 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}