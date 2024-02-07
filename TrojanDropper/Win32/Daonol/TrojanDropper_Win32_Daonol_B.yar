
rule TrojanDropper_Win32_Daonol_B{
	meta:
		description = "TrojanDropper:Win32/Daonol.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 79 73 61 75 64 69 6f 2e 73 79 73 00 } //01 00 
		$a_01_1 = {61 75 78 00 } //02 00  畡x
		$a_00_2 = {6d 00 69 00 65 00 6b 00 69 00 65 00 6d 00 6f 00 65 00 73 00 20 00 72 00 75 00 6c 00 65 00 73 00 } //02 00  miekiemoes rules
		$a_03_3 = {4e 83 fe 00 7c 16 b8 19 00 00 00 e8 90 01 02 ff ff 83 c0 61 88 03 43 4e 83 fe ff 75 ea c6 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}