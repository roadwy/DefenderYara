
rule Trojan_Win32_Alureon_FF{
	meta:
		description = "Trojan:Win32/Alureon.FF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {76 0b 80 34 08 90 01 01 40 3b 44 24 04 72 f5 90 00 } //02 00 
		$a_01_1 = {8a c8 80 c1 5a 30 0c 30 40 3b c5 72 f3 } //02 00 
		$a_01_2 = {8a d0 80 c2 54 30 14 30 40 3b c1 72 f3 } //01 00 
		$a_01_3 = {5b 50 41 4e 45 4c 5f 53 49 47 4e 5f 43 48 45 43 4b 5d } //01 00  [PANEL_SIGN_CHECK]
		$a_01_4 = {47 45 54 5f 50 41 52 41 4d 53 } //01 00  GET_PARAMS
		$a_01_5 = {5b 72 65 66 65 72 65 72 5f 65 6e 64 5d } //00 00  [referer_end]
	condition:
		any of ($a_*)
 
}