
rule Trojan_Win32_Tracur_AC{
	meta:
		description = "Trojan:Win32/Tracur.AC,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 3a 5c 64 65 76 5c 63 62 5f 6c 6f 61 64 65 72 5c 52 65 6c 65 61 73 65 5c 63 62 5f 6c 6f 61 64 65 72 2e 70 64 62 } //01 00 
		$a_01_1 = {3d 2e 4a 50 47 74 21 3d 2e 6a 70 67 74 1a 3d 2e 65 78 65 74 13 3d 2e 74 6d 70 74 0c 3d 2e 45 58 45 74 05 3d 2e 54 4d 50 } //01 00 
		$a_01_2 = {8b 79 08 8a 14 07 88 14 3e 83 c0 01 83 c6 01 3b 41 0c 72 ec } //00 00 
	condition:
		any of ($a_*)
 
}