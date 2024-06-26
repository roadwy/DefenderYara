
rule PWS_Win32_Sinowal_gen_X{
	meta:
		description = "PWS:Win32/Sinowal.gen!X,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 17 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 7d fc 1d 90 03 04 05 73 90 01 01 0f 83 90 01 04 90 03 05 06 8b 55 90 01 01 ff 75 90 01 01 5a c1 e2 04 90 03 05 06 8b 45 90 01 01 ff 75 90 01 01 58 c1 e8 05 90 00 } //0a 00 
		$a_01_1 = {03 44 11 0c 50 e8 } //0a 00 
		$a_03_2 = {42 65 65 70 90 09 02 00 81 90 03 01 01 38 3a 90 01 04 90 03 01 02 74 0f 84 90 00 } //0a 00 
		$a_01_3 = {81 e2 00 ff 00 00 81 fa 00 45 00 00 75 } //0a 00 
		$a_01_4 = {6a 08 68 aa 00 00 00 8d 45 f4 50 e8 } //01 00 
		$a_01_5 = {81 7d fc 01 17 00 00 73 } //01 00 
		$a_01_6 = {81 7d f8 89 2a 00 00 73 } //01 00 
		$a_01_7 = {81 7d fc c7 32 00 00 73 } //01 00 
		$a_01_8 = {81 7d fc 9b 63 00 00 73 } //01 00 
		$a_01_9 = {81 7d fc a1 75 00 00 73 } //01 00 
		$a_01_10 = {81 7d f4 a9 78 00 00 73 } //01 00 
		$a_01_11 = {81 7d f8 a9 78 00 00 73 } //01 00 
		$a_01_12 = {81 7d f4 69 a8 00 00 73 } //01 00 
		$a_03_13 = {81 7d f4 54 bc 00 00 90 03 01 02 73 0f 83 90 00 } //01 00 
		$a_01_14 = {81 7d fc 54 bc 00 00 73 } //01 00 
		$a_01_15 = {81 7d fc 50 c3 00 00 73 } //01 00 
		$a_01_16 = {81 7d fc c1 c3 00 00 73 } //01 00 
		$a_03_17 = {81 7d f4 58 cc 00 00 90 03 01 02 73 0f 83 90 00 } //01 00 
		$a_01_18 = {81 7d fc 58 cc 00 00 73 } //01 00 
		$a_01_19 = {81 7d fc 37 c7 00 00 73 } //01 00 
		$a_01_20 = {81 7d f4 49 d7 00 00 73 } //01 00 
		$a_01_21 = {81 7d fc 49 d7 00 00 73 } //01 00 
		$a_01_22 = {81 7d f4 0b fc 00 00 73 } //00 00 
	condition:
		any of ($a_*)
 
}