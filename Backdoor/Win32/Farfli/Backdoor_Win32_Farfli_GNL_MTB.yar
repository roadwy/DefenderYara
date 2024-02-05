
rule Backdoor_Win32_Farfli_GNL_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {b0 41 b3 6c 68 90 01 04 51 88 44 24 90 01 01 c6 44 24 90 01 01 44 c6 44 24 90 01 01 56 88 44 24 90 01 01 c6 44 24 90 01 01 50 c6 44 24 90 01 01 49 c6 44 24 90 01 01 33 c6 44 24 90 01 01 32 c6 44 24 90 01 01 2e c6 44 24 90 01 01 64 88 5c 24 90 01 01 88 5c 24 90 01 01 c6 44 24 90 00 } //01 00 
		$a_01_1 = {50 6c 75 67 69 6e 4d 65 31 } //00 00 
	condition:
		any of ($a_*)
 
}