
rule Trojan_Win32_Exrand{
	meta:
		description = "Trojan:Win32/Exrand,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 03 00 "
		
	strings :
		$a_00_0 = {00 63 6f 66 66 65 65 62 6f 6f 6b 2e 63 6f 2e 6b 72 00 00 } //02 00 
		$a_01_1 = {45 56 54 5f 46 44 30 41 34 46 34 30 2d 30 33 34 30 2d 34 30 61 62 } //02 00  EVT_FD0A4F40-0340-40ab
		$a_00_2 = {44 31 42 41 43 31 41 42 2d 39 32 32 30 2d 34 33 35 66 2d 38 39 46 46 2d 45 38 33 31 34 46 38 37 34 33 37 42 } //01 00  D1BAC1AB-9220-435f-89FF-E8314F87437B
		$a_00_3 = {5c 73 79 73 74 65 6d 33 32 5c 00 00 5c 73 79 73 74 65 6d 5c } //01 00 
		$a_00_4 = {25 73 5c 68 6f 73 74 73 2e 73 61 6d } //00 00  %s\hosts.sam
	condition:
		any of ($a_*)
 
}