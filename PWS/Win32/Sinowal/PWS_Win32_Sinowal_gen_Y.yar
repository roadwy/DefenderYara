
rule PWS_Win32_Sinowal_gen_Y{
	meta:
		description = "PWS:Win32/Sinowal.gen!Y,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 04 4a 0f b6 4d 10 03 c1 } //01 00 
		$a_03_1 = {81 e1 00 f0 00 00 81 f9 00 40 00 00 90 03 02 01 0f 85 75 90 00 } //01 00 
		$a_03_2 = {0f b7 51 12 81 e2 00 20 00 00 90 03 01 02 75 0f 85 90 00 } //01 00 
		$a_03_3 = {8b 45 0c 03 90 03 06 04 85 90 01 02 ff ff 45 90 01 01 50 ff 55 90 00 } //02 00 
		$a_03_4 = {3e 3e ff 75 0c 58 03 90 03 06 04 85 90 01 02 ff ff 45 90 01 01 50 ff 55 90 00 } //01 00 
		$a_03_5 = {03 34 91 33 c6 90 0a 40 00 c1 e0 04 90 02 04 c1 e9 05 33 c1 90 02 08 83 e2 03 90 00 } //01 00 
		$a_03_6 = {8b 4d 0c 03 90 03 06 04 8d 90 01 02 ff ff 4d 90 01 01 51 ff 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}