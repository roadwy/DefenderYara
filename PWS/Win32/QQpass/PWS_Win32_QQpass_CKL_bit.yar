
rule PWS_Win32_QQpass_CKL_bit{
	meta:
		description = "PWS:Win32/QQpass.CKL!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 36 30 74 72 61 79 } //01 00  360tray
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 51 51 2e 45 58 45 } //01 00  taskkill /im QQ.EXE
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {26 70 61 73 73 77 6f 72 64 3d 31 26 6f 70 5f 74 79 70 65 3d 61 64 64 } //00 00  &password=1&op_type=add
	condition:
		any of ($a_*)
 
}