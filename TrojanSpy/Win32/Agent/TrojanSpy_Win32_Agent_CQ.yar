
rule TrojanSpy_Win32_Agent_CQ{
	meta:
		description = "TrojanSpy:Win32/Agent.CQ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {c7 80 fc 02 00 00 22 c8 00 00 e8 90 01 04 b2 01 a1 58 ad 46 00 e8 90 01 04 8b 55 fc 89 82 f8 02 00 00 90 00 } //02 00 
		$a_03_1 = {05 fc 02 00 00 b9 04 00 00 00 8b d3 e8 90 01 04 83 c3 04 8d 45 f8 b9 04 00 00 00 8b d3 e8 90 01 04 83 c3 04 8b 45 fc 05 00 03 00 00 8b 55 f8 90 00 } //01 00 
		$a_01_2 = {53 63 72 65 65 6e 20 43 61 70 74 75 72 65 } //01 00 
		$a_01_3 = {43 61 6d 6d 79 } //00 00 
	condition:
		any of ($a_*)
 
}