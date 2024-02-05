
rule Backdoor_Win32_TCmdGall_A_dha{
	meta:
		description = "Backdoor:Win32/TCmdGall.A!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 54 68 72 65 61 64 20 6f 66 20 52 65 61 64 53 68 65 6c 6c 28 53 65 6e 64 29 20 45 72 72 6f 72 2e } //01 00 
		$a_01_1 = {43 72 65 61 74 65 54 68 72 65 61 64 20 6f 66 20 57 72 69 74 65 53 68 65 6c 6c 28 52 65 63 76 29 20 45 72 72 6f 72 2e } //01 00 
		$a_01_2 = {4e 50 43 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}