
rule Trojan_Win32_SysWiper_GY_MTB{
	meta:
		description = "Trojan:Win32/SysWiper.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,50 00 50 00 08 00 00 "
		
	strings :
		$a_01_0 = {45 72 72 6f 72 20 6f 70 65 6e 69 6e 67 20 64 72 69 76 65 2e 20 43 6f 64 65 3a } //10 Error opening drive. Code:
		$a_01_1 = {44 72 69 76 65 20 68 61 6e 64 6c 65 20 6f 70 65 6e 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //10 Drive handle opened successfully
		$a_01_2 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 72 65 61 64 20 66 69 72 73 74 20 73 65 63 74 6f 72 } //10 Successfully read first sector
		$a_01_3 = {43 68 65 63 6b 69 6e 67 20 70 72 69 76 69 6c 65 67 65 73 2e 2e 2e } //10 Checking privileges...
		$a_01_4 = {50 72 6f 67 72 61 6d 20 69 73 20 4e 4f 54 20 72 75 6e 6e 69 6e 67 20 61 73 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 2e } //10 Program is NOT running as Administrator.
		$a_01_5 = {50 72 6f 67 72 61 6d 20 72 75 6e 6e 69 6e 67 20 77 69 74 68 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 70 72 69 76 69 6c 65 67 65 73 } //10 Program running with Administrator privileges
		$a_01_6 = {50 72 6f 67 72 61 6d 20 66 69 6e 69 73 68 65 64 20 73 61 66 65 6c 79 2e } //10 Program finished safely.
		$a_01_7 = {53 74 61 63 6b 20 61 72 6f 75 6e 64 20 74 68 65 20 76 61 72 69 61 62 6c 65 } //10 Stack around the variable
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10) >=80
 
}