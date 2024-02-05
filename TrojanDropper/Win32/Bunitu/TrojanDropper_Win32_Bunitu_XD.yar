
rule TrojanDropper_Win32_Bunitu_XD{
	meta:
		description = "TrojanDropper:Win32/Bunitu.XD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {89 45 fc 87 4d fc 33 4d fc 87 4d fc 8b 45 fc c7 05 d8 ee 44 00 00 00 00 00 8b c8 01 0d d8 ee 44 00 a1 f0 ee 44 00 8b 0d d8 ee 44 00 89 08 } //01 00 
		$a_03_1 = {b8 02 30 00 00 48 48 50 ff 90 01 02 ff 90 01 02 ff 35 90 01 04 5a 68 90 01 03 00 52 c3 90 00 } //01 00 
		$a_03_2 = {83 c0 7b 8b 0d 90 01 04 8b 15 90 01 04 66 89 44 4a 14 90 00 } //01 00 
		$a_03_3 = {83 c0 7d 8b 0d 90 01 04 8b 15 90 01 04 66 89 44 4a 5e 90 00 } //01 00 
		$a_00_4 = {ba 52 14 40 00 83 ea 02 52 } //00 00 
	condition:
		any of ($a_*)
 
}