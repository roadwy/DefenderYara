
rule Virus_Win32_Cutef_B{
	meta:
		description = "Virus:Win32/Cutef.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 86 80 00 00 00 5e 03 c6 83 c0 0c 8b 18 81 3c 33 4b 45 52 4e 75 0c 81 } //01 00 
		$a_01_1 = {7c 33 04 45 4c 33 32 75 02 eb 05 83 c0 14 eb e4 83 e8 0c 83 c0 10 8b 00 } //01 00 
		$a_01_2 = {8b 04 30 25 00 f0 ff ff 8d 9d b6 14 40 00 53 64 67 ff 36 00 00 64 67 89 } //01 00 
		$a_01_3 = {26 00 00 66 81 38 4d 5a 74 } //00 00 
	condition:
		any of ($a_*)
 
}