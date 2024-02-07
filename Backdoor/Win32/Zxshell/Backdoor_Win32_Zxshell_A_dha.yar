
rule Backdoor_Win32_Zxshell_A_dha{
	meta:
		description = "Backdoor:Win32/Zxshell.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 58 53 6f 63 6b 50 72 6f 78 79 20 5b 2d 62 5d 20 3c 50 6f 72 74 3e 20 5b 2d 75 5d 20 3c 55 73 65 72 6e 61 6d 65 3e 20 5b 2d 70 5d 20 3c 50 61 73 73 77 6f 72 64 3e } //01 00  ZXSockProxy [-b] <Port> [-u] <Username> [-p] <Password>
		$a_01_1 = {72 75 6e 61 73 20 75 73 65 72 20 70 61 73 73 77 6f 72 64 20 74 65 73 74 2e 65 78 65 20 20 28 72 75 6e 20 74 65 73 74 2e 65 78 65 20 61 73 20 75 73 65 72 29 0d 0a } //01 00 
		$a_01_2 = {53 68 61 72 65 53 68 65 6c 6c 20 49 50 20 50 6f 72 74 20 2d 6e 63 0d 0a } //00 00 
	condition:
		any of ($a_*)
 
}