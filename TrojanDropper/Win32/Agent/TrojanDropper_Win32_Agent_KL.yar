
rule TrojanDropper_Win32_Agent_KL{
	meta:
		description = "TrojanDropper:Win32/Agent.KL,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {42 00 69 00 6e 00 64 00 46 00 69 00 6c 00 65 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 } //02 00  BindFile Microsoft
		$a_01_1 = {42 00 69 00 6e 00 64 00 46 00 69 00 6c 00 65 00 2e 00 45 00 58 00 45 00 } //03 00  BindFile.EXE
		$a_01_2 = {42 00 69 00 6e 00 64 00 46 00 69 00 6c 00 65 00 28 00 26 00 41 00 29 00 2e 00 2e 00 2e 00 } //00 00  BindFile(&A)...
	condition:
		any of ($a_*)
 
}