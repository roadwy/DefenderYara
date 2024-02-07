
rule Backdoor_Win32_SSrat_A{
	meta:
		description = "Backdoor:Win32/SSrat.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 35 74 46 40 00 e8 ae 1b 00 00 89 c3 83 fb ff 75 04 31 c0 eb 05 b8 01 00 00 00 } //01 00 
		$a_01_1 = {4d 49 4e 49 53 45 52 56 53 53 00 } //01 00 
		$a_01_2 = {43 46 47 00 6f 70 65 6e 00 38 35 34 7c 00 } //01 00  䙃G灯湥㠀㐵|
		$a_01_3 = {57 69 6e 55 70 64 61 74 65 00 53 53 52 41 54 } //01 00 
		$a_01_4 = {77 69 6e 73 76 63 68 6f 73 74 73 2e 65 78 65 00 } //01 00 
		$a_01_5 = {5c 52 75 6e 00 33 34 7c 00 } //00 00 
	condition:
		any of ($a_*)
 
}