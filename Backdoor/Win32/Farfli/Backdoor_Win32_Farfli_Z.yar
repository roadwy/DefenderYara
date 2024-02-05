
rule Backdoor_Win32_Farfli_Z{
	meta:
		description = "Backdoor:Win32/Farfli.Z,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 79 43 72 65 61 74 65 4d 61 00 } //03 00 
		$a_01_1 = {25 73 5c 50 61 72 61 6d 65 74 65 72 73 } //04 00 
		$a_01_2 = {5b 25 30 32 75 2d 25 30 32 75 2d 25 64 20 25 30 32 75 3a 25 30 32 75 3a 25 30 32 75 5d 20 28 25 73 29 } //00 00 
	condition:
		any of ($a_*)
 
}