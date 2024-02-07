
rule TrojanClicker_Win32_Olilat_A{
	meta:
		description = "TrojanClicker:Win32/Olilat.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {4a 00 4f 00 45 00 7a 00 5c 00 42 00 6f 00 77 00 74 00 73 00 5c 00 4d 00 2d 00 79 00 2d 00 4c 00 2d 00 69 00 2d 00 72 00 2d 00 61 00 2d 00 74 00 5c 00 } //01 00  JOEz\Bowts\M-y-L-i-r-a-t\
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 64 00 75 00 72 00 6c 00 2e 00 6e 00 65 00 74 00 } //01 00  http://adurl.net
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 79 00 77 00 65 00 62 00 72 00 65 00 73 00 75 00 6c 00 74 00 73 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 63 00 6c 00 69 00 65 00 6e 00 74 00 31 00 32 00 34 00 2e 00 68 00 74 00 6d 00 6c 00 } //01 00  http://mywebresults.info/client124.html
		$a_01_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 73 00 2e 00 6d 00 79 00 6e 00 61 00 61 00 67 00 65 00 6e 00 63 00 69 00 65 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 3f 00 64 00 62 00 3d 00 38 00 } //00 00  http://ps.mynaagencies.com/?db=8
	condition:
		any of ($a_*)
 
}