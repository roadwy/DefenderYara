
rule Spyware_Win32_Coolwebsearch_L{
	meta:
		description = "Spyware:Win32/Coolwebsearch.L,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 65 61 72 63 68 2d 2d 63 6f 6e 74 72 6f 6c 2e 63 6f 6d } //02 00  search--control.com
		$a_01_1 = {73 75 70 70 6f 72 74 2e 70 68 70 3f 79 7a 3d 79 65 73 } //02 00  support.php?yz=yes
		$a_01_2 = {55 4c 57 69 6e 64 6f 77 53 65 65 6b } //02 00  ULWindowSeek
		$a_01_3 = {73 65 72 74 39 38 2e 72 65 67 } //02 00  sert98.reg
		$a_01_4 = {73 65 72 74 58 50 2e 72 65 67 } //00 00  sertXP.reg
	condition:
		any of ($a_*)
 
}