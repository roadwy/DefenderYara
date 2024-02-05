
rule Backdoor_Win32_Farfli_GMC_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {22 31 1b 2f 99 32 41 79 00 67 4c 40 21 0e } //01 00 
		$a_01_1 = {40 56 50 72 6f 74 65 63 74 } //01 00 
		$a_01_2 = {5a 71 4c 32 47 41 31 4f 54 } //00 00 
	condition:
		any of ($a_*)
 
}