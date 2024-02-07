
rule TrojanDropper_Win32_Jhee_V{
	meta:
		description = "TrojanDropper:Win32/Jhee.V,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 10 89 50 04 89 50 08 89 50 0c ff d7 99 b9 1a 00 00 00 be 01 00 00 00 f7 f9 80 c2 61 3b de 88 55 00 7e 19 ff d7 } //01 00 
		$a_02_1 = {62 68 6f 2e 64 6c 6c 90 02 10 70 6c 61 79 2e 64 6c 6c 90 02 10 73 65 72 2e 65 78 65 90 00 } //01 00 
		$a_02_2 = {31 2e 72 6d 90 02 10 31 2e 74 78 74 90 02 10 31 2e 62 6d 70 90 02 10 31 2e 65 78 65 90 00 } //01 00 
		$a_00_3 = {66 75 63 6b 79 6f 75 } //00 00  fuckyou
	condition:
		any of ($a_*)
 
}