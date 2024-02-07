
rule Trojan_Win32_Swrort_A_{
	meta:
		description = "Trojan:Win32/Swrort.A!!Swrort.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 29 80 6b 00 } //01 00 
		$a_01_1 = {68 ea 0f df e0 } //01 00 
		$a_01_2 = {68 c2 db 37 67 } //01 00 
		$a_01_3 = {68 b7 e9 38 ff } //01 00 
		$a_01_4 = {68 74 ec 3b e1 } //01 00 
		$a_01_5 = {68 75 6e 4d 61 } //01 00  hunMa
		$a_01_6 = {68 63 6d 64 00 } //01 00 
		$a_01_7 = {68 79 cc 3f 86 } //02 00 
		$a_03_8 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 90 01 04 ff d5 90 00 } //04 00 
		$a_01_9 = {3b 7d 24 75 e4 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 } //02 00 
		$a_03_10 = {ff d5 3c 06 7c 0a 80 fb e0 75 05 bb 90 01 04 6a 00 53 ff d5 90 00 } //05 00 
	condition:
		any of ($a_*)
 
}