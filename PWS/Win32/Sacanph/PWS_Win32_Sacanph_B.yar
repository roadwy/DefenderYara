
rule PWS_Win32_Sacanph_B{
	meta:
		description = "PWS:Win32/Sacanph.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 63 74 69 6f 6e 3d 61 64 64 26 61 3d } //02 00  action=add&a=
		$a_02_1 = {3c 2f 55 73 65 72 3e 90 02 10 3c 50 61 73 73 3e 90 02 10 3c 2f 50 61 73 73 3e 90 02 10 3c 50 6f 72 74 3e 90 02 10 3c 2f 50 6f 72 74 3e 90 00 } //02 00 
		$a_02_2 = {6f 72 69 67 69 6e 5f 75 72 6c 90 02 10 26 6c 3d 90 02 10 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 90 00 } //01 00 
		$a_00_3 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  \Google\Chrome\User Data\Default\Login Data
		$a_00_4 = {5c 46 69 6c 65 5a 69 6c 6c 61 5c 72 65 63 65 6e 74 73 65 72 76 65 72 73 2e 78 6d 6c } //01 00  \FileZilla\recentservers.xml
		$a_00_5 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c } //00 00  \Mozilla\Firefox\Profiles\
	condition:
		any of ($a_*)
 
}