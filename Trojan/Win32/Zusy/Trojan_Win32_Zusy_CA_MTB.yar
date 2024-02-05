
rule Trojan_Win32_Zusy_CA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {46 73 6f 69 61 73 67 69 6f 73 67 69 6f 73 61 67 69 6a 73 64 } //02 00 
		$a_01_1 = {4a 69 6f 6a 61 65 6f 69 67 6a 61 69 65 67 6a 61 64 } //02 00 
		$a_01_2 = {4d 69 6a 66 67 69 65 67 66 61 68 73 75 67 68 73 61 64 75 } //02 00 
		$a_01_3 = {4f 49 6f 69 6a 73 67 39 38 30 73 65 67 69 6f 73 67 68 6a } //01 00 
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_CA_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 d7 09 fb 83 e7 90 02 04 09 fe f7 d3 bf 90 02 04 31 c6 8b 45 90 02 04 09 f3 88 18 b4 90 02 04 b3 90 02 04 2a 65 90 02 04 28 e3 be 90 02 04 81 fe 90 00 } //01 00 
		$a_03_1 = {31 fe f7 d3 83 f6 90 02 04 89 5d 90 00 } //01 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_01_3 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}