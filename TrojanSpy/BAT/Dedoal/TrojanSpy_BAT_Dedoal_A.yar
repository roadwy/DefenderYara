
rule TrojanSpy_BAT_Dedoal_A{
	meta:
		description = "TrojanSpy:BAT/Dedoal.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 6f 6e 69 74 6f 72 65 57 45 42 } //01 00  MonitoreWEB
		$a_01_1 = {53 6d 61 72 74 49 72 63 34 6e 65 74 57 45 42 } //01 00  SmartIrc4netWEB
		$a_01_2 = {44 6f 77 6e 41 6c 6c } //01 00  DownAll
		$a_01_3 = {52 65 73 74 61 72 74 61 46 6f 72 55 41 43 } //01 00  RestartaForUAC
		$a_01_4 = {44 65 74 65 63 74 41 56 } //01 00  DetectAV
		$a_01_5 = {47 42 45 78 69 73 74 73 } //01 00  GBExists
		$a_01_6 = {44 65 74 65 63 74 41 6e 64 43 6c 65 61 6e } //00 00  DetectAndClean
		$a_00_7 = {5d 04 00 00 } //4a 3c 
	condition:
		any of ($a_*)
 
}