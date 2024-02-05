
rule PWS_Win32_Stawin_C{
	meta:
		description = "PWS:Win32/Stawin.C,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 04 00 "
		
	strings :
		$a_01_0 = {80 f9 0d 74 0f 80 f9 1b 74 0a 80 f9 08 74 05 80 f9 09 75 } //02 00 
		$a_01_1 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //02 00 
		$a_01_2 = {48 6f 6f 6b 65 72 2e 64 6c 6c } //02 00 
		$a_01_3 = {43 69 74 69 62 61 6e 6b } //00 00 
	condition:
		any of ($a_*)
 
}