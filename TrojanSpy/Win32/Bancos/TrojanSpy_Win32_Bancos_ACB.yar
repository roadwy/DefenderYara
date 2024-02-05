
rule TrojanSpy_Win32_Bancos_ACB{
	meta:
		description = "TrojanSpy:Win32/Bancos.ACB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {be 01 00 00 00 8d 45 f0 8b 55 fc 8a 54 32 ff 8b cf 2a d1 e8 } //02 00 
		$a_01_1 = {8b 55 fc 8b c3 8b 08 ff 51 38 8d 4d f0 ba f4 01 00 00 b8 } //01 00 
		$a_00_2 = {2e 62 62 2e 63 6f 6d 2e 62 72 } //01 00 
		$a_00_3 = {69 74 61 75 2e 63 6f 6d } //01 00 
		$a_00_4 = {70 61 72 61 20 61 63 65 73 73 61 72 20 6f 20 69 6e 74 65 72 6e 65 74 20 62 61 6e 6b 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}