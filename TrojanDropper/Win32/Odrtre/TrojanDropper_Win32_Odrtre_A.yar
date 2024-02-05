
rule TrojanDropper_Win32_Odrtre_A{
	meta:
		description = "TrojanDropper:Win32/Odrtre.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {0f 00 c0 09 c0 0f 85 90 01 01 00 00 00 } //01 00 
		$a_02_1 = {81 c4 00 01 00 00 be 90 01 02 40 00 ad 83 f8 01 74 2e 83 f8 02 74 75 83 f8 03 0f 84 b7 00 00 00 83 f8 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}