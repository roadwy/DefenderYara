
rule Trojan_Win32_RunningRAT_A_dha{
	meta:
		description = "Trojan:Win32/RunningRAT.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 20 00 00 05 00 "
		
	strings :
		$a_01_0 = {00 52 4d 2d 4d 20 3a 20 53 74 61 72 74 00 } //05 00 
		$a_01_1 = {00 52 4d 2d 4d 20 3a 20 46 69 6e 64 52 65 73 6f 75 72 63 65 41 20 46 61 69 6c 65 64 00 } //05 00 
		$a_01_2 = {00 52 4d 2d 4d 20 3a 20 4c 6f 61 64 52 65 73 6f 75 72 63 65 20 66 61 69 6c 65 64 00 } //05 00 
		$a_01_3 = {00 52 4d 2d 4d 20 3a 20 4c 6f 61 64 52 65 73 6f 75 72 63 65 20 4f 4b 21 00 } //05 00 
		$a_01_4 = {00 52 4d 2d 4d 20 3a 20 75 6e 63 6f 6d 70 72 65 73 73 20 4f 4b 21 00 } //05 00 
		$a_01_5 = {00 52 4d 2d 4d 20 3a 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 20 46 61 69 6c 65 64 20 25 64 00 } //05 00 
		$a_01_6 = {00 52 4d 2d 4d 20 3a 20 4c 6f 61 64 4c 69 62 72 61 72 79 41 20 46 61 69 6c 65 64 20 25 73 20 2d 20 25 64 00 } //05 00 
		$a_01_7 = {00 52 4d 2d 4d 20 3a 20 45 6e 74 72 79 50 6f 69 6e 74 46 75 6e 63 20 4f 4b 21 00 } //05 00 
		$a_01_8 = {00 4d 52 20 2d 20 41 6c 72 65 61 64 79 20 45 78 69 73 74 65 64 00 } //05 00 
		$a_01_9 = {00 4d 52 20 3a 20 25 30 34 64 2d 25 30 32 64 2d 25 30 32 64 2d 25 30 32 64 2d 25 30 32 64 2d 25 30 32 64 00 } //05 00 
		$a_01_10 = {00 4d 52 20 46 69 72 73 74 20 53 74 61 72 74 65 64 2c 20 52 65 67 69 73 74 65 64 20 4f 4b 21 00 } //05 00 
		$a_01_11 = {00 53 79 73 74 65 6d 52 61 74 2e 64 6c 6c 00 } //05 00 
		$a_01_12 = {00 52 75 6e 6e 69 6e 67 52 61 74 00 } //05 00 
		$a_01_13 = {00 64 6b 65 6f 72 6b 63 6c 5f 65 6b 6c 73 64 6c 5f 31 32 33 5f 32 33 39 32 38 33 34 37 32 39 } //05 00 
		$a_01_14 = {00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 20 52 75 6e 6e 69 6e 67 52 61 74 00 } //05 00 
		$a_01_15 = {00 53 79 73 52 61 74 00 } //03 00 
		$a_01_16 = {00 69 78 65 6f 35 38 34 2e 62 69 6e 00 } //01 00 
		$a_01_17 = {00 50 61 72 65 6e 74 44 6c 6c 2e 64 6c 6c 00 } //01 00 
		$a_01_18 = {43 3a 5c 55 53 45 52 53 5c 50 75 62 6c 69 63 5c 72 65 73 75 6c 74 2e 6c 6f 67 } //01 00 
		$a_01_19 = {00 47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 20 3a 20 25 73 00 } //01 00 
		$a_01_20 = {00 50 61 72 65 6e 74 20 3a 20 25 73 00 } //01 00 
		$a_01_21 = {00 00 00 00 70 75 74 72 61 74 53 41 53 57 00 00 00 00 } //01 00 
		$a_01_22 = {00 00 00 00 70 75 6e 61 65 6c 43 41 53 57 00 00 00 00 } //01 00 
		$a_01_23 = {00 00 00 00 74 70 6f 6b 63 6f 73 74 65 73 00 00 00 00 } //01 00 
		$a_01_24 = {00 00 00 00 74 63 65 6e 6e 6f 63 00 00 00 00 } //01 00 
		$a_01_25 = {00 00 00 00 73 6e 6f 74 68 00 00 00 00 } //01 00 
		$a_01_26 = {00 00 00 00 65 6d 61 6e 79 62 74 73 6f 68 74 65 67 00 00 00 00 } //01 00 
		$a_01_27 = {00 00 00 00 74 65 6b 63 6f 73 00 00 00 00 } //01 00 
		$a_01_28 = {00 00 00 00 74 63 65 6c 65 73 00 00 00 00 } //01 00 
		$a_01_29 = {00 00 00 00 65 6d 61 6e 6b 63 6f 73 74 65 67 00 00 00 00 } //01 00 
		$a_01_30 = {00 00 00 00 65 6d 61 6e 74 73 6f 68 74 65 67 00 00 00 00 } //01 00 
		$a_01_31 = {00 00 00 00 74 65 6b 63 6f 73 65 73 6f 6c 63 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}