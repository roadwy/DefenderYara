
rule Worm_Win32_Tisandr_CB_MTB{
	meta:
		description = "Worm:Win32/Tisandr.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 6f 75 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 20 77 69 74 68 20 53 79 73 74 65 6d } //01 00  You has been infected with System
		$a_01_1 = {42 65 73 74 5f 70 69 63 74 75 72 65 73 31 39 39 32 2e 65 78 65 } //01 00  Best_pictures1992.exe
		$a_00_2 = {57 65 6c 63 6f 6d 65 20 37 31 35 34 4e 44 52 34 } //01 00  Welcome 7154NDR4
		$a_01_3 = {66 75 63 6b 65 72 5f 62 72 6f 6d 61 73 2e 65 78 65 } //01 00  fucker_bromas.exe
		$a_01_4 = {68 61 63 6b 69 6e 67 20 65 6e 20 65 73 70 61 c3 b1 6f 6c 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}