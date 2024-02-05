
rule Trojan_Win32_Killav_DR{
	meta:
		description = "Trojan:Win32/Killav.DR,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 0f 00 00 05 00 "
		
	strings :
		$a_03_0 = {00 61 6e 74 69 5f 61 76 90 0f 01 00 2e 64 6c 6c 00 90 00 } //05 00 
		$a_01_1 = {66 c7 45 ea 0f 04 } //04 00 
		$a_03_2 = {8b 45 e8 0f be 08 85 c9 74 90 01 01 8b 55 e8 0f be 02 83 e8 90 01 01 8b 4d e8 88 01 90 00 } //04 00 
		$a_03_3 = {8b 55 f0 8a 02 50 e8 90 01 02 ff ff 83 c4 04 0f be f0 8b 4d f4 8a 11 52 e8 90 01 02 ff ff 83 c4 04 0f be c0 3b f0 75 90 01 01 b0 90 01 01 b0 90 00 } //01 00 
		$a_01_4 = {00 7a 61 75 6e 69 6e 73 74 2e 65 78 65 } //02 00 
		$a_01_5 = {00 5c 53 65 74 75 70 5c 73 65 74 69 66 61 63 65 2e 64 6c 6c 22 2c 52 75 6e 53 65 74 75 70 } //01 00 
		$a_01_6 = {00 2f 74 55 6e 49 6e 73 74 61 6c 6c } //01 00 
		$a_01_7 = {00 6d 63 75 6e 69 6e 73 74 } //01 00 
		$a_01_8 = {00 2f 52 45 4d 4f 56 45 } //01 00 
		$a_01_9 = {00 67 20 64 61 74 61 00 } //01 00 
		$a_01_10 = {00 73 6f 75 70 38 38 00 } //01 00 
		$a_01_11 = {00 74 76 66 31 00 } //01 00 
		$a_01_12 = {00 70 6f 73 74 69 6e 73 74 61 } //01 00 
		$a_00_13 = {00 42 75 74 74 6f 6e 00 00 41 56 47 } //01 00 
		$a_01_14 = {00 63 61 6c 6c 6d 73 69 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}