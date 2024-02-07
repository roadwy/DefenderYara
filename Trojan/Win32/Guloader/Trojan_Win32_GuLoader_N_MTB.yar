
rule Trojan_Win32_GuLoader_N_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {53 63 68 69 63 6b } //03 00  Schick
		$a_81_1 = {44 65 63 6f 6c 6f 72 69 73 69 6e 67 36 2e 64 61 74 } //03 00  Decolorising6.dat
		$a_81_2 = {72 6f 74 74 65 64 65 73 } //03 00  rottedes
		$a_81_3 = {73 6c 77 67 61 } //03 00  slwga
		$a_81_4 = {53 65 63 75 72 69 74 79 2d 53 50 50 2d 47 65 6e 75 69 6e 65 4c 6f 63 61 6c 53 74 61 74 75 73 } //03 00  Security-SPP-GenuineLocalStatus
		$a_81_5 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //03 00  NtQuerySystemInformation
		$a_81_6 = {45 74 77 45 76 65 6e 74 45 6e 61 62 6c 65 64 } //00 00  EtwEventEnabled
	condition:
		any of ($a_*)
 
}