
rule Backdoor_Win32_PornDialer{
	meta:
		description = "Backdoor:Win32/PornDialer,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 61 73 44 69 61 6c 41 } //01 00 
		$a_01_1 = {73 68 69 6e 67 5c 54 72 75 73 74 20 44 61 74 61 62 61 73 65 5c 30 } //02 00 
		$a_01_2 = {53 79 73 57 65 62 53 6f 66 74 20 53 2e 52 2e 4c 2e } //02 00 
		$a_01_3 = {65 69 6e 65 72 20 30 31 39 30 2d 4e 75 6d 6d 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}