
rule Trojan_Win32_CobaltStrike_EB_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 1c 3e 02 1c 16 0f b6 fb 0f b6 1c 3e 8b 7d 90 01 01 8b 75 90 01 01 32 1c 07 88 1c 06 40 39 45 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_EB_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 55 08 89 55 08 8b 45 0c 2b 45 ec 8b 4d 10 1b 4d f0 89 45 0c 89 4d 10 } //01 00 
		$a_01_1 = {5c 00 70 00 69 00 70 00 65 00 5c 00 43 00 59 00 4d 00 5f 00 6f 00 75 00 74 00 70 00 75 00 74 00 70 00 69 00 70 00 65 00 5f 00 36 00 33 00 62 00 65 00 33 00 34 00 34 00 30 00 32 00 65 00 32 00 64 00 38 00 66 00 36 00 38 00 37 00 65 00 64 00 61 00 35 00 32 00 65 00 37 00 } //01 00  \pipe\CYM_outputpipe_63be34402e2d8f687eda52e7
		$a_01_2 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 2c 00 54 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 2c 00 70 00 72 00 6f 00 63 00 65 00 78 00 70 00 2e 00 65 00 78 00 65 00 2c 00 70 00 72 00 6f 00 63 00 65 00 78 00 70 00 36 00 34 00 2e 00 65 00 78 00 65 00 2c 00 70 00 65 00 72 00 66 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00  explorer.exe,Taskmgr.exe,procexp.exe,procexp64.exe,perfmon.exe
		$a_01_3 = {68 00 69 00 64 00 65 00 5f 00 66 00 69 00 6c 00 65 00 2c 00 68 00 69 00 64 00 65 00 5f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //01 00  hide_file,hide_process
		$a_01_4 = {2e 00 43 00 79 00 6d 00 43 00 72 00 79 00 70 00 74 00 } //01 00  .CymCrypt
		$a_01_5 = {62 00 61 00 63 00 6b 00 75 00 70 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 00 2c 00 20 00 74 00 68 00 69 00 73 00 20 00 66 00 69 00 6c 00 65 00 20 00 77 00 69 00 6c 00 6c 00 20 00 6e 00 6f 00 74 00 20 00 62 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //00 00  backup file %s, this file will not be encrypted
	condition:
		any of ($a_*)
 
}