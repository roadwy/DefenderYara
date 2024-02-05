
rule TrojanSpy_Win32_Camec_AR{
	meta:
		description = "TrojanSpy:Win32/Camec.AR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 95 50 ff ff ff 6a 38 52 ff d6 8d 85 40 ff ff ff 6a 37 50 ff d6 8d 8d 20 ff ff ff 6a 36 } //01 00 
		$a_01_1 = {43 61 70 74 63 68 61 5f 44 6f 63 5f 45 6d 70 72 65 73 61 00 } //01 00 
		$a_01_2 = {2d 00 2d 00 58 00 75 00 30 00 32 00 3d 00 24 00 2d 00 2d 00 } //01 00 
		$a_00_3 = {41 64 6f 62 65 20 46 6c 61 73 68 20 50 6c 61 79 65 72 } //01 00 
		$a_00_4 = {65 78 74 72 61 74 6f } //00 00 
	condition:
		any of ($a_*)
 
}