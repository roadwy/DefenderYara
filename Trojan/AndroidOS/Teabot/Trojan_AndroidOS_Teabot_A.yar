
rule Trojan_AndroidOS_Teabot_A{
	meta:
		description = "Trojan:AndroidOS/Teabot.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 76 69 64 65 6f 2f 66 61 6e 74 61 73 79 2f 61 6d 6f 75 6e 74 2f 61 70 69 } //01 00 
		$a_01_1 = {67 65 74 50 68 6f 6e 65 73 49 6e 53 65 74 } //01 00 
		$a_01_2 = {61 67 65 6e 74 73 6f 6d 65 6f 6e 65 } //01 00 
		$a_01_3 = {61 64 64 72 65 73 73 73 6f 72 72 79 } //02 00 
		$a_01_4 = {41 4a 6a 4e 74 44 75 52 7a 4c 69 4e 6f 4c 6b 48 71 45 62 46 63 4d 63 50 70 57 65 4e 66 55 6a 53 6b } //02 00 
		$a_01_5 = {41 4f 74 45 6f 57 6d 5a 70 4c 66 4b 6c 41 6d 51 65 51 6c 47 74 4b 63 41 67 41 65 43 6d 48 6b 49 6e 52 77 4c 66 4b 64 4e 6f 44 77 55 62 51 61 55 6b } //00 00 
	condition:
		any of ($a_*)
 
}