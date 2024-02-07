
rule TrojanDropper_Win32_Daonol_D{
	meta:
		description = "TrojanDropper:Win32/Daonol.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {20 45 78 49 73 54 20 22 43 3a 5c 5f 2e } //01 00   ExIsT "C:\_.
		$a_02_1 = {64 65 6c 20 22 43 3a 5c 90 01 01 2e 62 61 74 22 90 00 } //02 00 
		$a_00_2 = {4d 00 69 00 65 00 6b 00 69 00 65 00 6d 00 6f 00 65 00 73 00 20 00 72 00 75 00 6c 00 65 00 73 00 } //01 00  Miekiemoes rules
		$a_02_3 = {8a 4c 02 ff 80 f1 90 01 01 88 4c 02 ff 4a 75 f2 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}