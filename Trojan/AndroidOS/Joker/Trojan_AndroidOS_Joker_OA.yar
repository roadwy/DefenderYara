
rule Trojan_AndroidOS_Joker_OA{
	meta:
		description = "Trojan:AndroidOS/Joker.OA,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 33 2e 31 32 32 2e 31 34 33 2e 32 36 2f 61 70 69 2f 63 6b 77 6b 73 6c 3f 69 63 63 3d } //02 00 
		$a_00_1 = {4c 63 6f 6d 2f 73 74 61 72 74 61 70 70 2f 61 6e 64 72 6f 69 64 2f 70 75 62 6c 69 73 68 } //02 00 
		$a_01_2 = {52 65 6d 6f 74 65 20 43 6c 6f 61 6b } //02 00 
		$a_00_3 = {63 6c 6f 61 6b 65 64 3a 20 6e 6f 20 6d 6f 72 65 20 74 72 69 61 6c } //02 00 
		$a_00_4 = {63 57 64 51 66 45 70 52 67 54 72 59 73 55 68 49 69 4f 79 50 6c 41 6d 53 76 44 77 46 74 47 7a 48 6a 4a 6b 4b 75 4c 61 5a 62 58 65 43 78 56 6e 42 6f 4e 71 4d } //00 00 
	condition:
		any of ($a_*)
 
}