
rule TrojanDropper_Win32_Rustock_B{
	meta:
		description = "TrojanDropper:Win32/Rustock.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 38 00 0f 84 90 01 02 00 00 80 38 00 74 90 01 01 81 38 65 6d 33 32 74 03 40 eb 90 00 } //01 00 
		$a_03_1 = {66 c7 44 10 ff 5f 00 6a 01 68 90 01 02 40 00 68 90 01 02 40 00 ff 15 8c 80 40 00 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 40 68 90 01 02 40 00 ff 15 90 01 02 40 00 83 f8 ff 75 14 6a 01 68 90 01 02 40 00 68 90 01 02 40 00 ff 15 90 01 02 40 00 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}