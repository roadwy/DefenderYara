
rule Virus_Win32_Netop_A{
	meta:
		description = "Virus:Win32/Netop.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c3 2c 8b fb 33 c0 47 38 07 90 01 02 8b 47 fc 0d 20 20 20 20 3d 2e 65 78 65 90 01 02 3d 2e 73 63 72 90 00 } //01 00 
		$a_02_1 = {96 66 81 3e 4d 5a 0f 85 90 01 02 00 00 03 76 3c 66 81 3e 50 45 0f 85 90 01 04 81 7e 08 6b 72 61 64 90 00 } //01 00 
		$a_02_2 = {c7 46 24 20 00 00 e0 8b 85 90 01 04 8b 58 28 89 9d 90 01 04 8b 9d 90 01 04 89 58 28 8b 5e 0c 03 5e 08 89 58 50 c7 40 08 6b 72 61 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}