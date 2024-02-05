
rule Backdoor_Win32_DialXS{
	meta:
		description = "Backdoor:Win32/DialXS,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 6e 6c 2f } //03 00 
		$a_01_1 = {28 43 29 44 69 61 6c 58 53 } //02 00 
		$a_01_2 = {4c 69 63 65 6e 73 65 20 76 6f 69 6c 61 74 65 64 } //01 00 
		$a_01_3 = {52 61 73 53 65 74 45 6e 74 72 79 50 72 6f 70 65 72 74 69 65 73 41 } //01 00 
		$a_01_4 = {50 72 6f 78 79 45 6e 61 62 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_DialXS_2{
	meta:
		description = "Backdoor:Win32/DialXS,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 69 61 6c 58 53 2e 4f 63 78 } //02 00 
		$a_01_1 = {44 69 61 6c 58 53 57 6e 64 43 6c 61 73 73 } //01 00 
		$a_01_2 = {44 69 61 6c 58 53 2e 48 4c 50 } //02 00 
		$a_01_3 = {44 69 61 6c 58 53 43 74 6c } //02 00 
		$a_01_4 = {28 43 29 44 69 61 6c 58 53 2c 20 68 74 74 70 3a 2f 2f 64 69 61 6c 78 73 2e 6e 6c } //02 00 
		$a_01_5 = {68 74 74 70 3a 2f 2f 78 30 2e 6e 6c 2f 69 6e 73 74 61 6c 6c 2f } //02 00 
		$a_01_6 = {68 74 74 70 3a 2f 2f 64 69 61 6c 78 73 2e 6e 6c 2f 69 6e 73 74 61 6c 6c 2f } //00 00 
	condition:
		any of ($a_*)
 
}