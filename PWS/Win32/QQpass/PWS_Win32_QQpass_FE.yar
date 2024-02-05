
rule PWS_Win32_QQpass_FE{
	meta:
		description = "PWS:Win32/QQpass.FE,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 64 72 61 77 5f 2e 52 65 67 69 73 74 65 72 53 70 65 63 69 61 6c 43 61 73 65 } //02 00 
		$a_01_1 = {5c 64 6c 6c 63 61 63 68 65 5c 64 64 72 61 77 2e 64 6c 6c } //02 00 
		$a_01_2 = {25 73 3f 64 38 30 3d 32 26 64 31 30 3d 25 73 } //02 00 
		$a_01_3 = {51 51 59 58 5f 44 4c 4c 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}