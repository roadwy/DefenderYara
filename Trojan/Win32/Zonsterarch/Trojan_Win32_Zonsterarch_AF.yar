
rule Trojan_Win32_Zonsterarch_AF{
	meta:
		description = "Trojan:Win32/Zonsterarch.AF,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 52 4f 44 5f 43 4f 4f 4b 49 45 5f 55 52 4c 3d } //01 00 
		$a_01_1 = {49 6e 74 65 72 6e 61 6c 41 75 74 6f 50 6f 70 75 70 4d 73 67 00 } //01 00 
		$a_01_2 = {43 75 73 74 6f 6d 65 72 52 65 67 57 65 62 53 69 74 65 55 52 4c } //01 00 
		$a_01_3 = {53 45 54 5f 50 41 59 50 41 47 45 5f 55 52 4c } //01 00 
		$a_01_4 = {4c 4f 47 56 41 52 4e 41 4d 45 50 41 49 44 } //01 00 
		$a_01_5 = {61 63 74 69 6f 6e 3d 7b 41 43 54 49 4f 4e 5f 49 44 7d 26 } //00 00 
	condition:
		any of ($a_*)
 
}