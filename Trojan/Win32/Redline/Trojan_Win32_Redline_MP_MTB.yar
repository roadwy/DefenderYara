
rule Trojan_Win32_Redline_MP_MTB{
	meta:
		description = "Trojan:Win32/Redline.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 83 65 fc 00 8b 45 10 90 01 45 fc 8b 45 08 8b 4d fc 89 08 c9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_MP_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 68 00 75 00 79 00 69 00 73 00 20 00 73 00 6f 00 66 00 6f 00 67 00 20 00 6c 00 65 00 73 00 61 00 6d 00 75 00 77 00 61 00 6c 00 69 00 79 00 } //05 00 
		$a_01_1 = {63 00 61 00 67 00 61 00 70 00 69 00 7a 00 61 00 67 00 65 00 73 00 69 00 } //05 00 
		$a_01_2 = {6a 00 65 00 77 00 75 00 77 00 6f 00 6d 00 65 00 6b 00 6f 00 72 00 65 00 63 00 6f 00 6b 00 6f 00 79 00 75 00 6a 00 65 00 73 00 61 00 63 00 } //01 00 
		$a_01_3 = {4d 6f 76 65 46 69 6c 65 57 69 74 68 50 72 6f 67 72 65 73 73 57 } //01 00 
		$a_01_4 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 49 64 } //00 00 
	condition:
		any of ($a_*)
 
}