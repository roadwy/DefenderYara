
rule Trojan_AndroidOS_DroidKrungFu_H{
	meta:
		description = "Trojan:AndroidOS/DroidKrungFu.H,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 6c 61 6e 3d 7a 68 26 63 6f 75 6e 74 72 79 3d 43 4e 26 6e 65 74 77 6f 72 6b 3d } //01 00 
		$a_03_1 = {26 70 61 64 3d 30 26 6d 61 3d 32 2e 33 2e 90 01 01 2c 41 6e 64 72 6f 69 64 25 32 30 90 00 } //02 00 
		$a_01_2 = {61 64 2e 67 6f 6e 67 66 75 2d 61 6e 64 72 6f 69 64 2e 63 6f 6d 3a 37 35 30 30 2f 61 64 } //02 00 
		$a_01_3 = {64 64 2e 70 68 6f 6e 65 67 6f 38 2e 63 6f 6d 3a 37 35 30 30 2f 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}