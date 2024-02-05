
rule Trojan_Win32_Ramnit_AK{
	meta:
		description = "Trojan:Win32/Ramnit.AK,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 6e 63 69 6e 73 74 61 6c 6c 2e 64 6c 6c 00 43 6f 6d 6d 61 6e 64 52 6f 75 74 69 6e 65 00 4d 6f 64 75 6c 65 43 6f 64 65 00 53 74 61 72 74 52 6f 75 74 69 6e 65 00 53 74 6f 70 52 6f 75 74 69 6e 65 } //01 00 
		$a_01_1 = {5a 77 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 00 00 00 41 63 49 6e 6a 65 63 74 44 6c 6c 3a } //01 00 
		$a_01_2 = {54 68 69 73 20 0e 70 72 6f 67 67 61 6d 87 63 47 6e 1f 4f 74 e7 62 65 af cf 75 5f 98 69 06 44 4f 7e 53 03 6d 6f 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}