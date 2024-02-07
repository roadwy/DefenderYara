
rule PWS_Win32_Sinowal_gen_B{
	meta:
		description = "PWS:Win32/Sinowal.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 09 00 00 05 00 "
		
	strings :
		$a_01_0 = {69 64 3d 25 73 26 73 76 3d 25 75 26 } //02 00  id=%s&sv=%u&
		$a_00_1 = {26 55 6e 62 6c 6f 63 6b } //02 00  &Unblock
		$a_01_2 = {50 61 73 73 77 6f 72 64 32 } //01 00  Password2
		$a_01_3 = {4c 6f 67 69 6e 3a 22 25 73 } //01 00  Login:"%s
		$a_01_4 = {25 73 28 73 65 6c 65 63 74 29 3a } //01 00  %s(select):
		$a_00_5 = {23 33 32 37 37 30 } //01 00  #32770
		$a_01_6 = {26 52 65 6d 65 6d 62 65 72 20 74 68 69 73 20 61 6e 73 77 65 72 } //01 00  &Remember this answer
		$a_01_7 = {50 65 72 6d 69 73 73 69 6f 6e 44 6c 67 } //01 00  PermissionDlg
		$a_01_8 = {24 5f 32 33 34 31 32 33 33 2e 54 4d 50 } //00 00  $_2341233.TMP
	condition:
		any of ($a_*)
 
}