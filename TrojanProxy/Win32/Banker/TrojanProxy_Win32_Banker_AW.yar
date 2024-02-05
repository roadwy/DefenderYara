
rule TrojanProxy_Win32_Banker_AW{
	meta:
		description = "TrojanProxy:Win32/Banker.AW,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 43 4f 50 41 2e 65 78 65 00 } //01 00 
		$a_00_1 = {43 3a 5c 41 64 64 6f 62 2e 65 78 65 00 } //01 00 
		$a_00_2 = {2f 61 64 64 2e 70 68 70 00 } //01 00 
		$a_00_3 = {49 4f 4e 5c 52 55 4e 00 00 00 ff ff ff ff 0b 00 00 00 41 6c 74 65 72 6e 61 74 69 76 6f } //01 00 
		$a_03_4 = {ff ba 02 00 00 80 8b c3 e8 90 01 03 ff 33 c9 ba 90 01 02 50 00 8b c3 e8 90 01 03 ff 8b 4d fc ba 90 01 02 50 00 8b c3 e8 90 00 } //01 00 
		$a_03_5 = {84 c0 74 16 a1 90 01 02 50 00 8b 80 44 03 00 00 66 be eb ff e8 90 01 03 ff eb 1d 6a 00 6a 00 6a 00 68 90 01 02 50 00 68 90 01 02 50 00 8b c3 e8 90 01 03 ff 50 e8 90 00 } //00 00 
		$a_00_6 = {80 10 00 } //00 bb 
	condition:
		any of ($a_*)
 
}