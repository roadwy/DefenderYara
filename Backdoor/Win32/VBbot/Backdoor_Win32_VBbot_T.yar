
rule Backdoor_Win32_VBbot_T{
	meta:
		description = "Backdoor:Win32/VBbot.T,SIGNATURE_TYPE_PEHSTR_EXT,32 00 23 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {65 00 3e 00 30 00 7c 00 6c 00 70 00 68 00 70 00 7c 00 76 00 31 00 78 00 66 00 72 00 73 00 31 00 58 00 64 00 38 00 37 00 37 00 47 00 77 00 3b 00 38 00 36 00 7d 00 75 00 6d 00 75 00 66 00 65 00 2f 00 69 00 64 00 78 00 } //0a 00 
		$a_00_1 = {65 00 3e 00 30 00 7c 00 6c 00 70 00 68 00 70 00 7c 00 76 00 31 00 78 00 66 00 72 00 73 00 31 00 58 00 64 00 38 00 37 00 37 00 47 00 77 00 3b 00 38 00 36 00 7d 00 75 00 6d 00 75 00 66 00 32 00 65 00 66 00 79 00 } //0a 00 
		$a_00_2 = {25 00 68 00 76 00 69 00 6c 00 65 00 67 00 76 00 71 00 23 00 69 00 65 00 74 00 79 00 75 00 7c 00 } //0a 00 
		$a_00_3 = {3a 00 20 00 63 00 61 00 73 00 74 00 72 00 69 00 6f 00 6e 00 75 00 6c 00 20 00 } //0a 00 
		$a_00_4 = {6f 00 6d 00 62 00 72 00 6c 00 30 00 6a 00 6d 00 33 00 78 00 75 00 32 00 76 00 73 00 67 00 67 00 76 00 6f 00 6a 00 77 00 30 00 73 00 73 00 6c 00 } //02 00 
		$a_01_5 = {52 65 67 72 65 67 69 73 74 72 69 69 } //02 00 
		$a_01_6 = {6f 6c 65 61 64 78 } //02 00 
		$a_01_7 = {6f 6c 6c 65 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}