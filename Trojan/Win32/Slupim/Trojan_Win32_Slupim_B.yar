
rule Trojan_Win32_Slupim_B{
	meta:
		description = "Trojan:Win32/Slupim.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 0d f0 00 00 } //02 00 
		$a_01_1 = {ba 5c 00 00 00 b9 65 00 00 00 89 } //02 00 
		$a_01_2 = {5c 5c 2e 5c 70 69 70 65 5c 24 25 64 24 } //01 00  \\.\pipe\$%d$
		$a_01_3 = {74 79 70 65 3d 6a 70 67 26 } //01 00  type=jpg&
		$a_00_4 = {48 00 69 00 70 00 49 00 6d 00 61 00 67 00 65 00 } //00 00  HipImage
	condition:
		any of ($a_*)
 
}