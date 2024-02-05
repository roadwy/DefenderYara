
rule Trojan_Win32_Adload_GEM_MTB{
	meta:
		description = "Trojan:Win32/Adload.GEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2b c8 8b 45 08 d3 c8 33 05 14 70 62 00 5d c3 } //0a 00 
		$a_01_1 = {56 8b 35 14 70 62 00 8b ce 33 35 68 27 43 01 83 e1 1f d3 ce 85 f6 75 04 } //01 00 
		$a_01_2 = {4b 69 6c 6c 54 69 6d 65 72 } //01 00 
		$a_01_3 = {44 62 67 50 72 6f 6d 70 74 } //01 00 
		$a_01_4 = {44 6c 6c 49 6e 73 74 61 6c 6c } //01 00 
		$a_01_5 = {6b 4c 6f 61 64 65 72 4c 6f 63 6b } //01 00 
		$a_01_6 = {66 79 43 68 61 6e 67 65 4b 65 79 } //00 00 
	condition:
		any of ($a_*)
 
}