
rule Backdoor_Win32_Truvasys_C_dha{
	meta:
		description = "Backdoor:Win32/Truvasys.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 69 6e 78 73 79 73 2e 65 78 65 } //01 00 
		$a_01_1 = {72 65 73 64 6c 6c 78 2e 64 6c 6c } //01 00 
		$a_01_2 = {6c 69 62 65 61 79 33 32 2e 64 6c 6c } //01 00 
		$a_01_3 = {73 73 6c 65 61 79 33 32 2e 64 6c 6c } //01 00 
		$a_01_4 = {54 61 73 6b 4d 67 72 } //01 00 
		$a_01_5 = {70 61 72 61 6d 65 74 65 72 73 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}