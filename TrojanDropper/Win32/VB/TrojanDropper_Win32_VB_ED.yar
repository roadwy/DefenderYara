
rule TrojanDropper_Win32_VB_ED{
	meta:
		description = "TrojanDropper:Win32/VB.ED,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 52 43 34 } //01 00 
		$a_01_1 = {6d 6f 64 41 6e 56 4d 00 6d 6f 64 41 6e 53 42 00 6d 6f 64 4d 65 6d 45 78 65 63 } //01 00 
		$a_03_2 = {66 8b 45 e0 66 33 45 dc 0f bf c0 50 8d 45 c0 50 e8 90 01 04 8d 45 a0 50 8d 45 c0 50 8d 45 b0 50 e8 90 01 04 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}