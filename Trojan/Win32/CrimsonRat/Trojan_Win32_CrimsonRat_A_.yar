
rule Trojan_Win32_CrimsonRat_A_{
	meta:
		description = "Trojan:Win32/CrimsonRat.A!!CrimsonRat.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,14 00 14 00 14 00 00 01 00 "
		
	strings :
		$a_81_0 = {74 68 72 52 75 6e 69 6e 67 } //01 00  thrRuning
		$a_81_1 = {66 75 6e 54 68 72 65 61 64 } //01 00  funThread
		$a_81_2 = {66 75 6e 53 74 61 72 74 65 72 } //01 00  funStarter
		$a_81_3 = {6c 69 73 74 5f 70 72 6f 63 65 73 73 65 73 } //01 00  list_processes
		$a_81_4 = {73 65 65 5f 73 63 72 65 6e } //01 00  see_scren
		$a_81_5 = {69 73 5f 73 63 72 65 65 6e } //01 00  is_screen
		$a_81_6 = {70 75 73 68 5f 66 69 6c 65 } //01 00  push_file
		$a_81_7 = {67 65 74 5f 63 6f 6d 6d 61 6e 64 } //01 00  get_command
		$a_81_8 = {64 6f 5f 70 72 6f 63 65 73 73 } //01 00  do_process
		$a_81_9 = {6c 6f 6f 6b 75 70 44 72 69 76 65 73 } //01 00  lookupDrives
		$a_81_10 = {6c 6f 6f 6b 75 70 46 69 6c 65 73 } //01 00  lookupFiles
		$a_81_11 = {73 65 6e 64 53 65 61 72 63 68 } //01 00  sendSearch
		$a_81_12 = {63 68 65 63 6b 46 6f 6c 64 65 72 73 } //01 00  checkFolders
		$a_81_13 = {72 65 6d 76 55 73 65 72 } //01 00  remvUser
		$a_81_14 = {66 69 6c 65 73 4c 6f 67 73 } //01 00  filesLogs
		$a_81_15 = {73 65 74 5f 72 75 6e } //01 00  set_run
		$a_81_16 = {6e 6f 74 46 69 6c 64 65 72 73 } //01 00  notFilders
		$a_81_17 = {73 65 65 41 63 63 65 73 73 } //01 00  seeAccess
		$a_81_18 = {61 64 64 46 69 6c 65 73 } //01 00  addFiles
		$a_81_19 = {6c 6f 6f 6b 46 69 6c 65 73 } //00 00  lookFiles
	condition:
		any of ($a_*)
 
}