
rule PWS_Win32_Kapod_B{
	meta:
		description = "PWS:Win32/Kapod.B,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 50 65 72 66 6c 69 62 5c 25 33 2e 33 78 00 00 2e 73 72 66 00 00 00 00 2e 73 72 66 00 00 00 00 2e 64 6c 6c 00 } //0a 00 
		$a_00_1 = {72 65 67 73 69 64 2e 70 68 70 3f 77 69 6e 64 6f 77 73 5f 6e 61 6d 65 3d } //05 00  regsid.php?windows_name=
		$a_02_2 = {2e 6e 65 2e 6a 70 2f 90 02 10 2e 70 68 70 90 00 } //05 00 
		$a_00_3 = {5f 73 74 6f 70 2e 65 78 65 2e 74 78 74 } //01 00  _stop.exe.txt
		$a_00_4 = {26 65 6d 61 69 6c 5f 6e 61 6d 65 3d } //01 00  &email_name=
		$a_00_5 = {26 75 72 6c 5f 61 3d } //00 00  &url_a=
	condition:
		any of ($a_*)
 
}