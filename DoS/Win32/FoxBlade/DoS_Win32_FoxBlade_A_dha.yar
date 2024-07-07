
rule DoS_Win32_FoxBlade_A_dha{
	meta:
		description = "DoS:Win32/FoxBlade.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 72 69 76 65 72 73 3a 3a 24 49 4e 44 45 58 5f 41 4c 4c 4f 43 41 54 49 4f 4e } //1 Drivers::$INDEX_ALLOCATION
		$a_00_1 = {5c 00 5c 00 2e 00 5c 00 45 00 50 00 4d 00 4e 00 54 00 44 00 52 00 56 00 5c 00 25 00 75 00 } //1 \\.\EPMNTDRV\%u
		$a_03_2 = {53 00 65 00 c7 90 02 03 53 00 68 00 c7 90 02 03 75 00 74 00 c7 90 02 03 64 00 6f 00 90 00 } //1
		$a_03_3 = {53 5a 44 44 90 02 10 4d 5a 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}