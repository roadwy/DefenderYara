
rule Backdoor_Win32_Zekapab_A_dha{
	meta:
		description = "Backdoor:Win32/Zekapab.A!dha,SIGNATURE_TYPE_PEHSTR,05 00 05 00 10 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 31 31 78 30 30 31 31 30 30 31 31 00 } //01 00 
		$a_01_1 = {2d 44 4f 57 4e 4c 4f 41 44 5f 45 4e 44 2d } //01 00  -DOWNLOAD_END-
		$a_01_2 = {2d 44 4f 57 4e 4c 4f 41 44 5f 53 54 41 52 54 2d } //01 00  -DOWNLOAD_START-
		$a_01_3 = {43 4d 44 5f 45 58 45 43 55 54 45 } //01 00  CMD_EXECUTE
		$a_01_4 = {44 45 4c 45 54 45 5f 46 49 4c 45 53 } //01 00  DELETE_FILES
		$a_01_5 = {44 45 4c 45 54 45 5f 46 4f 4c 44 45 52 } //01 00  DELETE_FOLDER
		$a_01_6 = {44 4f 57 4e 4c 4f 41 44 5f 44 41 54 45 } //02 00  DOWNLOAD_DATE
		$a_01_7 = {46 49 4c 45 5f 45 58 45 43 55 54 45 5f 41 4e 44 5f 4b 69 4c 4c 5f 4d 59 53 45 4c 46 } //01 00  FILE_EXECUTE_AND_KiLL_MYSELF
		$a_01_8 = {4b 49 4c 4c 5f 50 52 4f 43 45 53 53 } //01 00  KILL_PROCESS
		$a_01_9 = {52 45 47 5f 47 45 54 5f 4b 45 59 53 5f 56 41 4c 55 45 53 } //01 00  REG_GET_KEYS_VALUES
		$a_01_10 = {55 50 4c 4f 41 44 5f 41 4e 44 5f 45 58 45 43 55 54 45 5f 46 49 4c 45 } //01 00  UPLOAD_AND_EXECUTE_FILE
		$a_01_11 = {55 50 4c 4f 41 44 5f 46 49 4c 45 } //01 00  UPLOAD_FILE
		$a_01_12 = {2f 43 68 65 63 6b 65 72 4e 6f 77 2d 73 61 4d 62 41 2d } //01 00  /CheckerNow-saMbA-
		$a_01_13 = {2f 43 68 65 63 6b 65 72 53 65 72 66 61 63 65 } //01 00  /CheckerSerface
		$a_01_14 = {2f 74 65 73 74 2d 43 65 72 74 69 66 69 63 61 74 65 73 } //01 00  /test-Certificates
		$a_01_15 = {2f 55 70 64 61 74 65 43 65 72 74 69 66 69 63 61 74 65 } //00 00  /UpdateCertificate
	condition:
		any of ($a_*)
 
}