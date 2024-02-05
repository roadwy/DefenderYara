
rule Trojan_MacOS_CloudMensis_B_MTB{
	meta:
		description = "Trojan:MacOS/CloudMensis.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 44 61 65 6d 6f 6e 73 2f 2e 63 6f 6d 2e 61 70 70 6c 65 2e 57 69 6e 64 6f 77 53 65 72 76 65 72 2e 70 6c 69 73 74 } //01 00 
		$a_00_1 = {2f 4c 69 62 72 61 72 79 2f 57 65 62 53 65 72 76 65 72 2f 73 68 61 72 65 2f 68 74 74 70 64 2f 6d 61 6e 75 61 6c 2f 57 69 6e 64 6f 77 53 65 72 76 65 72 } //01 00 
		$a_00_2 = {64 69 73 6b 75 74 69 6c 20 6d 6f 75 6e 74 20 2d 6d 6f 75 6e 74 50 6f 69 6e 74 20 2f 74 6d 70 2f 6d 6e 74 20 2f 64 65 76 2f 64 69 73 6b 30 73 31 } //01 00 
		$a_00_3 = {72 6d 20 2d 66 20 2f 74 6d 70 2f 6d 6e 74 2f 72 6f 6f 74 } //00 00 
	condition:
		any of ($a_*)
 
}