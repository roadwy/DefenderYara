
rule PWS_Win32_Cimuz_M_dll{
	meta:
		description = "PWS:Win32/Cimuz.M!dll,SIGNATURE_TYPE_PEHSTR_EXT,07 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 6f 78 4d 61 69 6c 50 61 73 73 77 6f 72 64 } //02 00 
		$a_01_1 = {50 61 73 73 77 6f 72 64 73 20 6f 66 20 41 75 74 6f 20 43 6f 6d 70 6c 65 74 65 } //02 00 
		$a_01_2 = {49 45 2f 46 54 50 2f 4f 75 74 4c 6f 6f 6b 20 50 61 73 73 77 6f 72 64 } //01 00 
		$a_01_3 = {57 69 6e 4e 54 2f 57 69 6e 32 4b 20 4c 6f 67 69 6e } //01 00 
		$a_01_4 = {35 65 37 65 38 31 30 30 } //00 00 
	condition:
		any of ($a_*)
 
}