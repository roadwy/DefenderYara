
rule Backdoor_Win32_Hupigon_ZO{
	meta:
		description = "Backdoor:Win32/Hupigon.ZO,SIGNATURE_TYPE_PEHSTR,3c 00 3c 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {33 36 30 73 61 66 65 } //0a 00 
		$a_01_1 = {6b 61 73 70 65 72 73 6b 79 } //0a 00 
		$a_01_2 = {5c 52 75 6e 4d 67 72 2e 45 58 45 } //0a 00 
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 44 65 62 75 67 2e 65 78 65 } //0a 00 
		$a_01_4 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 33 36 30 74 72 61 79 2e 65 78 65 } //0a 00 
		$a_01_5 = {3e 20 6e 75 6c } //00 00 
	condition:
		any of ($a_*)
 
}