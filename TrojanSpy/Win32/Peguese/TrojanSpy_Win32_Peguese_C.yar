
rule TrojanSpy_Win32_Peguese_C{
	meta:
		description = "TrojanSpy:Win32/Peguese.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 95 20 ff ff ff b8 90 01 04 e8 90 01 04 8b 85 20 ff ff ff e8 90 01 04 50 8b 45 fc 8b 80 20 04 00 00 90 00 } //05 00 
		$a_01_1 = {50 57 33 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 } //05 00 
		$a_01_2 = {41 73 44 75 6c 6c 68 69 6c 6c } //01 00  AsDullhill
		$a_03_3 = {6a 30 56 8d 95 90 01 01 fe ff ff b8 90 01 04 e8 90 01 02 ff ff 8b 85 90 01 01 fe ff ff e8 90 01 04 50 53 e8 90 01 04 6a 00 6a 00 6a 10 53 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}