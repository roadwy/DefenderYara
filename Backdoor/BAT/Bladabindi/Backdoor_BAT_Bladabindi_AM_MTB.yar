
rule Backdoor_BAT_Bladabindi_AM_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0d 09 2c 4e 09 6f 90 01 04 0a 06 7e 90 01 04 28 90 01 04 2d 1c 06 7e 90 01 04 28 90 01 04 2d 17 06 7e 90 01 04 28 90 01 04 2d 12 2b 18 7e 90 01 04 0b 2b 16 7e 90 01 04 0b 2b 0e 7e 90 01 04 0b 2b 06 90 00 } //03 00 
		$a_80_1 = {64 65 66 61 75 6c 74 42 72 6f 77 73 65 72 } //defaultBrowser  03 00 
		$a_80_2 = {47 65 74 49 6e 73 74 61 6c 6c 65 64 42 72 6f 77 73 65 72 } //GetInstalledBrowser  03 00 
		$a_80_3 = {73 68 6f 77 49 6e 5f 73 70 65 63 69 61 6c 5f 42 72 6f 77 73 65 72 } //showIn_special_Browser  03 00 
		$a_80_4 = {49 73 36 34 42 69 74 73 } //Is64Bits  03 00 
		$a_80_5 = {49 73 57 6f 77 36 34 50 72 6f 63 65 73 73 } //IsWow64Process  00 00 
	condition:
		any of ($a_*)
 
}