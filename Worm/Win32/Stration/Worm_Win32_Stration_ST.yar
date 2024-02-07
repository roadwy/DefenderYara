
rule Worm_Win32_Stration_ST{
	meta:
		description = "Worm:Win32/Stration.ST,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8d 49 00 8a 5c 04 0c 8a 4c 24 30 32 d9 88 5c 04 0c 40 83 f8 25 7c ec } //01 00 
		$a_03_1 = {57 8d 54 24 90 01 01 52 33 90 01 02 8d 44 90 01 02 50 68 90 01 06 c7 44 90 01 02 00 00 00 00 ff 15 90 01 04 8b f8 85 ff 74 24 6a ff 57 ff 15 90 01 04 8d 4c 90 01 02 51 57 ff 15 90 01 04 85 c0 74 04 90 00 } //01 00 
		$a_01_2 = {53 65 74 55 6e 68 61 6e 64 6c 65 64 45 78 63 65 70 74 69 6f 6e 46 69 6c 74 65 72 } //00 00  SetUnhandledExceptionFilter
	condition:
		any of ($a_*)
 
}