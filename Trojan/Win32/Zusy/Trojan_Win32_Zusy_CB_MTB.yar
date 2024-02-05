
rule Trojan_Win32_Zusy_CB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {f6 d2 80 e2 5a 08 fa 30 f2 08 d3 88 5d f1 81 fe 90 02 04 0f 8e 90 00 } //01 00 
		$a_01_1 = {89 c2 f7 d2 09 ca f7 d1 09 c1 f7 d2 f7 d1 89 d0 21 c8 31 d1 09 c1 89 4d } //01 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_01_3 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_CB_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {4f 49 6f 61 67 38 39 77 67 6f 69 65 67 68 61 73 65 67 69 68 } //02 00 
		$a_01_1 = {4f 49 6f 69 61 6a 66 67 39 38 61 6a 67 6f 69 61 6a 65 67 65 } //02 00 
		$a_01_2 = {56 66 67 6f 69 61 65 66 67 69 6f 75 61 65 6f 67 69 61 68 65 6a 67 } //02 00 
		$a_01_3 = {62 76 41 45 47 4f 69 6f 61 68 67 69 61 73 68 65 67 } //01 00 
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}