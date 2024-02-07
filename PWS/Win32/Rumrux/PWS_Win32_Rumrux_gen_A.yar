
rule PWS_Win32_Rumrux_gen_A{
	meta:
		description = "PWS:Win32/Rumrux.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 25 73 0d 0a 41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 35 2e 30 30 3b 20 25 73 29 0d 0a } //01 00 
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 63 6f 6e 6e 65 63 74 2e 0a 00 } //01 00 
		$a_01_2 = {5c 64 6c 6c 63 61 63 68 65 5c 76 65 72 63 6c 73 69 64 2e 65 78 65 00 } //01 00 
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 44 65 73 6b 74 6f 70 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop
		$a_00_4 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //01 00  Accept-Language: zh-cn
		$a_01_5 = {72 78 6d 72 75 00 } //00 00  硲牭u
	condition:
		any of ($a_*)
 
}