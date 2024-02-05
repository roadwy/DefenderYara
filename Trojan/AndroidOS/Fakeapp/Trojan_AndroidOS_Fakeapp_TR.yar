
rule Trojan_AndroidOS_Fakeapp_TR{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.TR,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6c 74 6f 3a 68 65 6c 70 40 6d 75 6c 74 69 6d 69 6e 65 2e 69 6e 66 6f } //01 00 
		$a_01_1 = {45 54 48 20 4d 69 6e 69 6e 67 20 69 73 20 43 75 72 72 65 6e 74 6c 79 20 52 75 6e 6e 69 6e 67 2e 20 50 6c 65 61 73 65 20 53 74 6f 70 20 41 66 74 65 72 20 79 6f 75 20 63 61 6e 20 57 69 74 68 64 72 61 77 20 53 61 74 6f 73 68 69 } //01 00 
		$a_01_2 = {6d 69 6c 6c 69 73 4c 65 66 74 42 43 48 } //00 00 
	condition:
		any of ($a_*)
 
}