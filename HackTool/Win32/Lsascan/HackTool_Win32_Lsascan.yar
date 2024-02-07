
rule HackTool_Win32_Lsascan{
	meta:
		description = "HackTool:Win32/Lsascan,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 63 68 6f 20 50 72 65 73 73 20 61 6e 79 20 4b 65 79 20 74 6f 20 45 58 49 54 20 2e 2e 2e 20 26 20 70 61 75 73 65 20 3e 20 6e 75 6c 00 } //01 00 
		$a_01_1 = {55 73 65 72 4e 61 6d 65 3a 20 25 53 } //01 00  UserName: %S
		$a_01_2 = {4c 6f 67 6f 6e 44 6f 6d 61 69 6e 3a 20 25 53 } //01 00  LogonDomain: %S
		$a_01_3 = {47 65 74 50 72 6f 63 65 73 73 48 61 6e 64 6c 65 42 79 4e 61 6d 65 20 66 61 69 6c 20 21 00 } //01 00 
		$a_01_4 = {45 6e 61 62 6c 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 20 66 61 69 6c 20 21 00 } //00 00 
	condition:
		any of ($a_*)
 
}