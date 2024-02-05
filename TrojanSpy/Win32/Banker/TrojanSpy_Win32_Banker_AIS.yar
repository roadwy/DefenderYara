
rule TrojanSpy_Win32_Banker_AIS{
	meta:
		description = "TrojanSpy:Win32/Banker.AIS,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {74 1e 8d 45 90 01 01 50 b9 01 00 00 00 8b d3 8b 45 90 01 01 e8 90 01 04 8b 55 90 01 01 8d 45 90 01 01 e8 90 01 04 43 4e 0f 85 90 00 } //01 00 
		$a_00_1 = {73 65 6e 68 61 } //01 00 
		$a_00_2 = {73 61 2a 6e 74 2a 61 6e 40 64 65 72 2e 40 63 23 6f 40 6d 2a } //01 00 
		$a_00_3 = {73 40 61 2a 6e 2a 74 23 61 6e 40 64 2a 65 40 72 23 6e 23 65 74 2a } //01 00 
		$a_00_4 = {2a 46 40 69 40 72 2a 65 23 66 } //01 00 
		$a_00_5 = {40 43 2a 61 23 69 2a 78 40 61 } //00 00 
	condition:
		any of ($a_*)
 
}