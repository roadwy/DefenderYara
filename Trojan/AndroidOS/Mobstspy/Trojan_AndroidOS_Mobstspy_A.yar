
rule Trojan_AndroidOS_Mobstspy_A{
	meta:
		description = "Trojan:AndroidOS/Mobstspy.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 6d 6f 63 2e 70 70 61 74 72 61 74 73 69 62 6f 6d 2e 77 77 77 2f 2f 3a 70 74 74 68 } //02 00 
		$a_00_1 = {23 57 68 61 74 73 41 70 70 2f 2f 4d 65 64 69 61 2f 2f 57 68 61 74 73 41 70 70 20 56 6f 69 63 65 20 4e 6f 74 65 73 23 23 41 43 52 43 61 6c 6c 73 23 23 43 61 6c 6c 52 65 63 6f 72 64 65 72 23 23 53 4d 65 6d 6f 23 23 44 43 49 4d 23 } //02 00 
		$a_00_2 = {2f 61 6d 2e 65 74 75 6f 72 65 64 6f 63 2e 77 77 77 2f 2f 3a 70 74 74 68 } //00 00 
	condition:
		any of ($a_*)
 
}