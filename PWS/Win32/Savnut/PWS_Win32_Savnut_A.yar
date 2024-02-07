
rule PWS_Win32_Savnut_A{
	meta:
		description = "PWS:Win32/Savnut.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 65 78 74 65 6e 73 69 6f 6e 73 } //01 00  Software\Mozilla\Firefox\extensions
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 63 41 66 65 65 5c 4d 53 43 } //01 00  SOFTWARE\McAfee\MSC
		$a_00_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 } //01 00  \\.\PhysicalDrive%d
		$a_00_3 = {25 73 6e 65 74 62 61 6e 6b 65 5f 25 73 5f 25 73 } //01 00  %snetbanke_%s_%s
		$a_02_4 = {2a 00 5c 2a 90 02 10 62 61 6e 6b 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}