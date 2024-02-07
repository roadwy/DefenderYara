
rule PWS_Win32_Raven_gen_A{
	meta:
		description = "PWS:Win32/Raven.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 77 63 78 5f 66 74 70 2e 69 6e 69 } //01 00  \wcx_ftp.ini
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //03 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {5f 6d 75 74 65 78 5f 66 69 6c 65 5f 66 61 6b 65 } //02 00  _mutex_file_fake
		$a_01_3 = {5f 65 76 65 6e 74 5f 75 70 64 5f 61 66 69 6c } //00 00  _event_upd_afil
	condition:
		any of ($a_*)
 
}