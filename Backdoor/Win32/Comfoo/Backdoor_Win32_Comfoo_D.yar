
rule Backdoor_Win32_Comfoo_D{
	meta:
		description = "Backdoor:Win32/Comfoo.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 c4 08 89 45 fc eb 1f 8b 45 f8 6b c0 32 05 } //02 00 
		$a_01_1 = {75 09 8b 4d f0 8b 51 04 89 55 f8 eb 8a 83 7d dc 00 74 0a 8b 45 dc 50 ff 15 } //01 00 
		$a_01_2 = {5c 73 63 72 65 65 6e 62 69 74 2e 62 6d 70 00 } //01 00 
		$a_01_3 = {4d 59 47 41 4d 45 48 41 56 45 53 54 41 52 54 00 } //01 00  奍䅇䕍䅈䕖呓剁T
		$a_01_4 = {5c 6d 73 74 65 6d 70 2e 74 65 6d 70 00 } //01 00 
		$a_01_5 = {70 65 72 66 64 69 2e 69 6e 69 00 } //01 00 
		$a_01_6 = {6d 73 70 6b 2e 73 79 73 00 } //01 00 
		$a_01_7 = {54 31 59 39 34 33 6a 49 68 6b 00 } //01 00 
		$a_01_8 = {63 3a 5c 74 65 6d 70 5c 61 62 63 61 62 63 2e 74 78 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}