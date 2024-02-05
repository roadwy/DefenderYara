
rule Trojan_AndroidOS_DroidRoot_T_MTB{
	meta:
		description = "Trojan:AndroidOS/DroidRoot.T!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 61 67 65 61 67 61 69 6e 73 74 74 68 65 63 61 67 65 } //01 00 
		$a_00_1 = {7a 34 72 6f 6f 74 } //01 00 
		$a_00_2 = {63 68 6f 77 6e 20 72 6f 6f 74 2e 72 6f 6f 74 20 73 79 73 74 65 6d 2f 62 69 6e 2f 73 75 5c 6e 63 68 6d 6f 64 20 36 37 35 35 20 2f 73 79 73 74 65 6d 2f 62 69 6e 2f 73 75 5c 6e } //0a 00 
		$a_03_3 = {00 12 0a 71 40 90 01 02 98 7a 0c 03 1a 08 90 01 01 00 22 09 90 01 01 00 1a 0a 90 01 01 00 70 20 90 01 01 00 a9 00 12 0a 44 0a 07 0a 6e 20 90 01 02 a9 00 0c 09 6e 10 90 01 02 09 00 0c 09 71 20 90 01 01 00 98 00 22 05 90 01 01 00 70 20 90 01 02 35 00 22 04 90 01 01 00 70 20 90 01 02 34 00 22 08 90 01 01 00 70 30 90 01 02 b8 04 6e 10 90 01 02 08 00 22 08 90 01 01 00 90 00 } //0a 00 
		$a_03_4 = {00 12 0b 71 40 90 01 02 a9 7b 0c 03 1a 09 90 01 01 00 22 09 90 01 01 00 1a 0a 90 01 01 00 70 20 90 01 02 a9 00 12 0a 44 0a 07 0a 6e 20 90 01 02 a9 00 0c 09 6e 10 90 01 02 09 00 0c 09 71 20 90 01 01 00 9c 00 22 05 90 01 01 00 70 20 90 01 02 35 00 22 04 90 01 01 00 70 20 90 01 02 34 00 22 09 90 01 01 00 70 40 90 01 02 d9 84 6e 10 90 01 02 09 00 1a 00 90 01 02 6e 10 90 01 02 00 00 0c 09 6e 20 90 01 02 95 00 6e 10 90 01 02 05 00 15 09 04 7f 1a 0a 90 01 02 6e 10 90 01 02 0d 00 0c 0b 71 30 90 01 02 a9 0b 14 09 02 00 04 7f 1a 0a 90 01 02 6e 10 90 01 02 0d 00 0c 0b 71 30 90 01 02 a9 0b 14 09 03 00 04 7f 1a 0a 90 01 02 6e 10 90 01 02 0d 00 0c 0b 71 30 90 01 02 a9 0b 22 09 90 01 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}