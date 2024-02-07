
rule Backdoor_Win32_Shell_D{
	meta:
		description = "Backdoor:Win32/Shell.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {ab 6a 11 33 c0 59 8d 7d ac f3 ab a1 } //01 00 
		$a_01_1 = {33 c0 8d 7d f0 6a 11 ab ab ab ab 59 33 c0 8d 7d ac f3 ab } //02 00 
		$a_01_2 = {50 c7 45 ac 44 00 00 00 c7 45 d8 01 01 00 00 66 89 45 dc 89 45 bc 89 45 c0 ff } //01 00 
		$a_01_3 = {62 47 39 6e 62 32 35 38 } //01 00  bG9nb258
		$a_01_4 = {73 64 6a 32 62 2e 33 33 32 32 2e 6f 72 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}