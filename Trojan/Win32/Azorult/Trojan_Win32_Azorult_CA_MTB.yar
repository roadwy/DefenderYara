
rule Trojan_Win32_Azorult_CA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {67 75 6a 75 6a 6f 78 65 66 69 79 6f 70 75 78 65 6d 75 67 61 } //03 00 
		$a_81_1 = {6e 6f 72 69 68 69 73 65 63 6f 64 6f 74 65 } //03 00 
		$a_81_2 = {5a 55 4b 41 4d 41 4a 49 4d 45 52 4f } //03 00 
		$a_81_3 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 45 78 57 } //03 00 
		$a_81_4 = {57 72 69 74 65 50 72 6f 66 69 6c 65 53 65 63 74 69 6f 6e 41 } //03 00 
		$a_81_5 = {47 65 74 4e 75 6d 61 48 69 67 68 65 73 74 4e 6f 64 65 4e 75 6d 62 65 72 } //03 00 
		$a_81_6 = {45 6e 75 6d 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 41 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_CA_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.CA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 c0 81 c4 14 11 00 00 c3 b8 40 1c 00 00 } //05 00 
		$a_01_1 = {8d 44 24 20 50 6a 00 ff d6 6a 00 8d 8c 24 54 0c 00 00 51 ff d7 8d 54 24 28 52 ff d3 8d 44 24 24 50 c7 44 24 28 00 00 00 00 ff d5 6a 00 8d 8c 24 54 14 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}