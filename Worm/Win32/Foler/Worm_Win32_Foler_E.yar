
rule Worm_Win32_Foler_E{
	meta:
		description = "Worm:Win32/Foler.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 4d 79 48 6f 6f 64 5c 00 00 00 00 77 69 6e 6c 73 61 2e 00 65 78 65 00 77 61 75 6c 74 2e 00 00 72 } //01 00 
		$a_01_1 = {55 73 62 50 72 6f 70 6f 67 61 74 6f 72 5c 74 65 73 74 5c 52 65 6c 65 61 73 65 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}