
rule Backdoor_Win32_CobaltStrikeLoader_PAA_MTB{
	meta:
		description = "Backdoor:Win32/CobaltStrikeLoader.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 44 20 46 69 6c 65 20 45 78 69 73 74 73 21 54 72 79 20 44 65 6c 65 74 65 21 } //01 00  BD File Exists!Try Delete!
		$a_81_1 = {4d 69 63 72 6f 53 6f 66 74 55 70 64 61 74 65 50 72 6f 63 65 73 73 49 44 } //01 00  MicroSoftUpdateProcessID
		$a_81_2 = {46 69 6c 65 20 44 6f 77 6e 6c 6f 61 64 20 53 75 63 63 65 73 73 2e } //01 00  File Download Success.
		$a_01_3 = {42 44 5f 66 69 6c 65 5f 64 6f 77 6e 6c 6f 61 64 5f 70 61 74 68 } //01 00  BD_file_download_path
		$a_01_4 = {42 44 5f 66 69 6c 65 5f 66 75 6c 6c 5f 70 61 74 68 } //01 00  BD_file_full_path
		$a_01_5 = {42 44 5f 66 69 6c 65 5f 6e 61 6d 65 } //01 00  BD_file_name
		$a_01_6 = {64 6f 77 6e 6c 6f 61 64 2e 65 78 65 } //01 00  download.exe
		$a_81_7 = {41 6e 74 69 2d 56 69 72 75 73 } //01 00  Anti-Virus
		$a_81_8 = {2f 63 68 65 63 6b 65 72 } //01 00  /checker
		$a_81_9 = {74 65 73 74 66 69 6c 65 } //00 00  testfile
	condition:
		any of ($a_*)
 
}