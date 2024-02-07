
rule Backdoor_Win32_Tapazom_G{
	meta:
		description = "Backdoor:Win32/Tapazom.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 54 4d 65 6d 6f 72 79 4c 6f 61 64 4c 69 62 61 72 79 } //01 00  BTMemoryLoadLibary
		$a_01_1 = {5c 6d 65 6c 74 20 22 00 } //01 00  浜汥⁴"
		$a_00_2 = {47 45 54 53 45 52 56 45 52 7c 00 } //00 00 
	condition:
		any of ($a_*)
 
}