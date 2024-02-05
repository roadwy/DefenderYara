
rule Trojan_Win32_LegionLoader_CPP_MTB{
	meta:
		description = "Trojan:Win32/LegionLoader.CPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {69 6f 76 67 73 65 69 6f 67 6a 65 38 39 34 67 73 65 69 6a 68 73 72 65 } //05 00 
		$a_01_1 = {6f 71 77 6f 70 65 69 6f 67 6a 73 65 61 67 6f 73 65 69 68 6a } //05 00 
		$a_01_2 = {73 68 69 6f 73 77 65 6a 67 33 38 77 39 67 6f 73 65 69 6a 73 65 68 } //05 00 
		$a_01_3 = {73 69 6f 73 65 6a 67 66 33 77 38 67 65 69 6f 6a 73 65 68 } //00 00 
	condition:
		any of ($a_*)
 
}