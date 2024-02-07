
rule Trojan_BAT_Darbl_A{
	meta:
		description = "Trojan:BAT/Darbl.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 74 5f 50 61 73 73 77 6f 72 64 73 } //01 00  set_Passwords
		$a_00_1 = {67 65 74 5f 50 61 73 73 77 6f 72 64 73 } //02 00  get_Passwords
		$a_00_2 = {00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 42 00 61 00 6c 00 64 00 72 00 2e 00 65 00 78 00 65 } //01 00 
		$a_00_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_00_4 = {55 70 6c 6f 61 64 44 61 74 61 } //01 00  UploadData
		$a_00_5 = {67 65 74 5f 52 75 6e 6e 69 6e 67 50 72 6f 63 65 73 73 } //01 00  get_RunningProcess
		$a_00_6 = {67 65 74 5f 49 6e 73 74 61 6c 6c 65 64 50 72 6f 67 72 61 6d 73 } //01 00  get_InstalledPrograms
		$a_00_7 = {67 65 74 5f 52 65 73 6f 6c 75 74 69 6f 6e } //01 00  get_Resolution
		$a_00_8 = {67 65 74 5f 48 57 49 44 } //02 00  get_HWID
		$a_02_9 = {4c 00 54 00 45 00 78 00 90 01 16 3d 00 90 00 } //00 00 
		$a_00_10 = {5d 04 00 00 c5 } //d0 03 
	condition:
		any of ($a_*)
 
}