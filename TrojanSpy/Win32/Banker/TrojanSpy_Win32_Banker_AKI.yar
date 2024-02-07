
rule TrojanSpy_Win32_Banker_AKI{
	meta:
		description = "TrojanSpy:Win32/Banker.AKI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 1e 8d 45 e0 50 b9 01 00 00 00 8b d3 90 01 58 00 2a 00 90 01 09 00 25 00 90 01 09 00 40 00 90 01 09 00 23 00 90 01 09 00 24 00 90 00 } //01 00 
		$a_01_1 = {5c 5f 41 73 44 75 6c 6c 68 69 6c 6c 42 68 6f 2e 70 61 73 } //01 00  \_AsDullhillBho.pas
		$a_01_2 = {70 6e 6c 53 61 6e 74 61 } //00 00  pnlSanta
	condition:
		any of ($a_*)
 
}