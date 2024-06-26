
rule PWS_Win32_Wowsteal_UV{
	meta:
		description = "PWS:Win32/Wowsteal.UV,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 04 00 "
		
	strings :
		$a_03_0 = {4a 50 c6 45 90 01 01 53 ff 75 e8 c6 45 90 01 01 5a c6 45 90 01 01 4c c6 45 90 01 01 2a c6 45 90 01 01 2a c6 45 90 01 01 2a 90 00 } //04 00 
		$a_03_1 = {6a 09 50 ff 35 90 01 04 c6 45 90 01 01 4d c6 45 90 01 01 5a c6 45 90 01 01 90 90 88 5d 90 01 01 c6 45 f0 03 88 5d f1 90 00 } //02 00 
		$a_01_2 = {25 64 25 64 78 78 78 2e 64 6c 6c 00 78 78 78 2e 64 6c 6c } //02 00 
		$a_03_3 = {6b 61 2e 69 6e 69 90 02 05 71 72 77 6f 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}