
rule TrojanSpy_Win32_Keylogger_AD{
	meta:
		description = "TrojanSpy:Win32/Keylogger.AD,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8d 85 e0 fe ff ff 50 e8 90 01 04 8d 8d dc fe ff ff b2 02 b0 15 e8 90 01 04 0f b6 46 08 88 45 eb 0f b7 46 0c c1 e8 08 88 45 ea 8d 8d d8 fe ff ff b2 01 b0 20 e8 90 00 } //0a 00 
		$a_00_1 = {52 51 53 b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff 5b 59 5a 33 c0 5a 59 59 64 89 10 eb } //01 00 
		$a_00_2 = {6e 74 2e 64 6c 6c 00 74 65 74 74 } //01 00 
		$a_00_3 = {5b 42 61 73 6c 61 74 5d } //00 00  [Baslat]
	condition:
		any of ($a_*)
 
}