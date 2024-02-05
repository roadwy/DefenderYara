
rule TrojanDropper_Win32_Frethog_N{
	meta:
		description = "TrojanDropper:Win32/Frethog.N,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 70 78 64 6e 64 2e 65 78 65 } //01 00 
		$a_00_1 = {75 70 78 64 6e 64 2e 64 6c 6c } //01 00 
		$a_00_2 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00 
		$a_00_3 = {35 31 33 34 33 32 38 31 } //01 00 
		$a_01_4 = {50 ff 15 24 20 40 00 8d 85 e0 fc ff ff 56 50 8d 85 e4 fd ff ff 50 ff d7 8d 85 e0 fc ff ff 68 cc 30 40 00 50 e8 52 08 00 00 8d 85 e0 fc ff ff 68 94 30 40 00 50 e8 41 08 00 00 83 c4 10 8d 85 e0 fc ff ff 53 50 8d 85 dc fb ff ff 50 ff 15 84 20 40 00 } //00 00 
	condition:
		any of ($a_*)
 
}