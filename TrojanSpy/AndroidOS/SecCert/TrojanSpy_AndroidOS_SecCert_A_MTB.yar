
rule TrojanSpy_AndroidOS_SecCert_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SecCert.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 5f 73 6d 73 5f 66 6f 72 77 61 72 64 69 6e 67 } //01 00 
		$a_00_1 = {55 53 53 44 44 75 6d 62 45 78 74 65 6e 64 65 64 4e 65 74 77 6f 72 6b } //01 00 
		$a_00_2 = {6e 75 6d 62 65 72 73 5f 74 6f 5f 73 6d 73 5f 64 69 76 65 72 74 } //01 00 
		$a_00_3 = {6e 75 6d 62 65 72 73 5f 74 6f 5f 63 61 6c 6c 5f 62 6c 6f 63 6b } //01 00 
		$a_03_4 = {4c 63 6f 6d 90 02 26 50 68 6f 6e 65 43 61 6c 6c 52 65 63 65 69 76 65 72 90 00 } //01 00 
		$a_00_5 = {73 65 6e 64 65 72 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 } //00 00 
		$a_00_6 = {5d 04 00 00 } //13 8f 
	condition:
		any of ($a_*)
 
}