
rule Trojan_AndroidOS_SpyAgent_D{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.D,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 70 65 72 66 65 63 74 2f 63 6f 6d 6d 75 6e 69 63 61 74 65 61 70 70 2f 4c 6f 63 61 6c 4d 65 73 73 61 67 65 } //01 00 
		$a_01_1 = {73 65 74 53 6d 73 62 6f 64 79 } //01 00 
		$a_01_2 = {4b 59 32 39 74 4c 6d 68 6c 65 58 52 68 63 43 35 76 63 47 56 75 61 57 51 75 53 55 39 77 5a 57 35 4a 52 41 } //01 00 
		$a_01_3 = {6d 61 72 6b 48 6f 73 74 4e 61 6d 65 46 61 69 6c 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}