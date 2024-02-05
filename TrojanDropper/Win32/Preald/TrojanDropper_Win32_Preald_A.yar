
rule TrojanDropper_Win32_Preald_A{
	meta:
		description = "TrojanDropper:Win32/Preald.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 48 8a 14 01 88 10 85 f6 75 f5 } //01 00 
		$a_03_1 = {46 8b c6 6b c0 0c 83 b8 90 01 04 00 75 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}