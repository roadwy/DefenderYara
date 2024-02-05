
rule Worm_Win32_Fakefolder_A{
	meta:
		description = "Worm:Win32/Fakefolder.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 06 52 ff 15 90 01 04 8b 44 24 90 01 01 6a 01 6a 00 50 68 90 01 04 68 90 01 04 6a 00 ff d3 90 00 } //01 00 
		$a_00_1 = {45 78 70 6c 6f 72 65 72 2e 45 58 45 00 00 00 00 6f 70 65 6e } //01 00 
		$a_00_2 = {00 70 6c 61 79 65 2e 6c 6f 67 00 } //01 00 
		$a_00_3 = {00 57 69 6e 53 78 53 5c 00 } //00 00 
	condition:
		any of ($a_*)
 
}