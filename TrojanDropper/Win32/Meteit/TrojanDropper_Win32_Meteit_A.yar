
rule TrojanDropper_Win32_Meteit_A{
	meta:
		description = "TrojanDropper:Win32/Meteit.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 49 47 4e 55 50 5c 2a 2e 69 6e 73 } //01 00 
		$a_03_1 = {5c 6d 73 61 64 6f 90 02 04 2e 90 00 } //01 00 
		$a_03_2 = {83 c4 14 8d 85 90 01 02 ff ff 68 90 01 04 50 8d 45 90 01 01 50 ff 15 90 01 04 8d 85 90 01 02 ff ff 50 8d 85 90 01 02 ff ff 50 ff 15 90 01 04 83 f8 ff 74 09 8d 85 90 01 02 ff ff 50 ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}