
rule TrojanSpy_Win32_Peguese_B{
	meta:
		description = "TrojanSpy:Win32/Peguese.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 95 f4 fe ff ff b8 90 01 03 00 e8 90 01 03 ff 8b 85 f4 fe ff ff e8 90 01 03 ff 50 8b 45 fc 8b 80 cc 03 00 00 50 90 00 } //01 00 
		$a_01_1 = {70 6a 63 74 32 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 } //00 00 
	condition:
		any of ($a_*)
 
}