
rule Trojan_MacOS_Amos_A_MTB{
	meta:
		description = "Trojan:MacOS/Amos.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 47 72 61 62 46 69 72 65 66 6f 78 } //01 00 
		$a_01_1 = {2e 46 69 6c 65 47 72 61 62 62 65 72 } //01 00 
		$a_01_2 = {2e 47 72 61 62 57 61 6c 6c 65 74 73 } //01 00 
		$a_01_3 = {6d 61 69 6e 2e 6b 65 79 63 68 61 69 6e 5f 65 78 74 72 61 63 74 } //01 00 
		$a_01_4 = {6d 61 69 6e 2e 73 65 6e 64 6c 6f 67 } //01 00 
		$a_01_5 = {2f 44 65 73 6b 74 6f 70 2f 61 6d 6f 73 20 62 75 69 6c 64 73 2f 53 6f 75 72 63 65 20 41 4d 4f 53 2f 63 6f 6e 66 2e 67 6f } //00 00 
	condition:
		any of ($a_*)
 
}