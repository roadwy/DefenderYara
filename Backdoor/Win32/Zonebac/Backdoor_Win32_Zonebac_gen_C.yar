
rule Backdoor_Win32_Zonebac_gen_C{
	meta:
		description = "Backdoor:Win32/Zonebac.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0b 00 08 00 00 04 00 "
		
	strings :
		$a_01_0 = {73 76 63 2e 65 78 65 00 6d 73 6d 70 73 76 63 2e 65 78 65 00 6d 70 65 6e } //04 00 
		$a_01_1 = {61 76 70 2e 65 78 65 00 63 61 76 74 72 61 79 2e 65 78 65 00 63 61 76 72 } //03 00 
		$a_00_2 = {7b 46 41 35 33 31 43 43 31 2d 31 34 39 37 2d 31 31 64 33 2d 41 31 38 30 2d 33 33 33 33 30 35 32 32 37 36 43 33 45 7d } //03 00  {FA531CC1-1497-11d3-A180-3333052276C3E}
		$a_01_3 = {75 70 64 61 74 65 2e 70 68 70 3f } //03 00  update.php?
		$a_01_4 = {26 46 49 52 45 57 41 4c 4c 53 3d 25 64 } //02 00  &FIREWALLS=%d
		$a_01_5 = {6a 14 99 59 f7 f9 83 c2 1e 69 d2 e8 03 00 00 52 } //02 00 
		$a_01_6 = {ff 74 24 04 6b c0 44 05 } //01 00 
		$a_00_7 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //00 00  AdjustTokenPrivileges
	condition:
		any of ($a_*)
 
}