
rule Trojan_Win32_Adpclient{
	meta:
		description = "Trojan:Win32/Adpclient,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 79 5f 4d 5f 69 5f 6e 69 54 5f 43 5f 50 43 5f 6c 69 65 6e 74 } //01 00 
		$a_01_1 = {45 52 52 4f 52 3a 67 66 73 20 20 20 57 41 49 54 } //01 00 
		$a_01_2 = {75 6e 5f 41 5f 44 5f 43 5f 6c 69 65 5f 6e 74 } //01 00 
		$a_01_3 = {76 64 66 30 33 6e 3a 66 61 6c 73 65 } //01 00 
		$a_01_4 = {67 33 39 39 34 38 65 6e 74 3a } //00 00 
	condition:
		any of ($a_*)
 
}