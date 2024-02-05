
rule Misleading_Win32_Chanicef{
	meta:
		description = "Misleading:Win32/Chanicef,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 64 00 6b 00 2d 00 73 00 6f 00 66 00 74 00 2e 00 6f 00 72 00 67 00 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //02 00 
		$a_01_2 = {41 64 76 61 6e 63 65 64 20 50 43 2d 4d 65 63 68 61 6e 69 63 } //02 00 
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 65 66 69 78 70 63 74 6f 6f 6c 73 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}