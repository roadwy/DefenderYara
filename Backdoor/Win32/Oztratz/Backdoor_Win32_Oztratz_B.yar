
rule Backdoor_Win32_Oztratz_B{
	meta:
		description = "Backdoor:Win32/Oztratz.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 81 e3 ff 00 00 00 8d 76 01 8a 94 1d f8 fe ff ff 0f b6 c2 03 c8 81 e1 ff 00 00 00 89 4d 08 0f b6 84 0d f8 fe ff ff 88 84 1d f8 fe ff ff 88 94 0d f8 fe ff ff 0f b6 8c 1d f8 fe ff ff 0f b6 c2 03 c8 81 e1 ff 00 00 00 0f b6 84 0d f8 fe ff ff 8b 4d fc 32 44 31 ff 8b 4d 08 88 46 ff 4f 75 a0 } //01 00 
		$a_01_1 = {4f 7a 6f 6e 65 20 52 41 54 } //01 00  Ozone RAT
		$a_01_2 = {64 61 74 61 2e 64 62 66 } //00 00  data.dbf
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}