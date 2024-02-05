
rule TrojanSpy_Win32_Gauss_plugin_B{
	meta:
		description = "TrojanSpy:Win32/Gauss.plugin!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {c6 45 fc 04 6a 00 6a 01 8d 75 d4 e8 90 01 04 8d 45 b4 50 8b f3 e8 90 01 04 8b 47 08 8d 8d 80 fd ff ff 51 50 e8 90 00 } //01 00 
		$a_02_1 = {50 6a 68 ff 15 90 01 04 3b c6 0f 84 90 01 04 83 f8 68 0f 87 90 01 04 8d 85 f0 fe ff ff 50 89 75 f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}