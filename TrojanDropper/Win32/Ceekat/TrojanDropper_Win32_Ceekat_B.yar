
rule TrojanDropper_Win32_Ceekat_B{
	meta:
		description = "TrojanDropper:Win32/Ceekat.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a fc 53 e8 90 01 02 ff ff 6a 00 8d 44 24 04 50 6a 04 8d 44 24 10 50 53 e8 90 01 02 ff ff 81 74 24 04 90 01 04 6a 00 90 00 } //01 00 
		$a_03_1 = {7e 19 8a 83 90 01 04 30 06 46 43 8b c3 bb 07 00 00 00 99 f7 fb 8b da 49 75 e7 90 00 } //01 00 
		$a_03_2 = {c6 00 55 b8 90 01 04 e8 90 01 02 ff ff c6 40 01 44 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}