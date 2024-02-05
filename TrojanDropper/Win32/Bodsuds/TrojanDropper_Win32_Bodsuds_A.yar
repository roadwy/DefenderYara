
rule TrojanDropper_Win32_Bodsuds_A{
	meta:
		description = "TrojanDropper:Win32/Bodsuds.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 7c 24 14 00 75 37 68 90 01 04 57 ff d6 59 59 85 c0 75 0e 57 8d 44 24 1c 50 ff 15 90 01 04 eb 0c 90 00 } //01 00 
		$a_03_1 = {68 00 00 00 c0 8d 85 90 01 02 ff ff 50 ff 15 90 01 04 89 85 90 01 02 ff ff c7 85 90 01 02 ff ff 4d 5a 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}