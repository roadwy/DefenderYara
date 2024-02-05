
rule Trojan_Win32_SmkLdr_H_MTB{
	meta:
		description = "Trojan:Win32/SmkLdr.H!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 09 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {5f 00 67 00 61 00 74 00 3d 00 } //02 00 
		$a_01_1 = {5f 00 5f 00 69 00 6f 00 3d 00 } //02 00 
		$a_01_2 = {43 00 6f 00 6f 00 6b 00 69 00 65 00 3a 00 20 00 5f 00 5f 00 67 00 61 00 64 00 73 00 3d 00 } //01 00 
		$a_01_3 = {47 00 45 00 54 00 } //01 00 
		$a_01_4 = {50 00 4f 00 53 00 54 00 } //01 00 
		$a_01_5 = {75 72 6c 28 22 } //01 00 
		$a_01_6 = {73 72 63 3d 22 } //00 00 
	condition:
		any of ($a_*)
 
}