
rule Backdoor_Win32_CobaltStrikeLoader_PAA_MTB{
	meta:
		description = "Backdoor:Win32/CobaltStrikeLoader.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {42 44 20 46 69 6c 65 20 45 78 69 73 74 73 21 54 72 79 20 44 65 6c 65 74 65 21 } //1 BD File Exists!Try Delete!
		$a_81_1 = {4d 69 63 72 6f 53 6f 66 74 55 70 64 61 74 65 50 72 6f 63 65 73 73 49 44 } //1 MicroSoftUpdateProcessID
		$a_81_2 = {46 69 6c 65 20 44 6f 77 6e 6c 6f 61 64 20 53 75 63 63 65 73 73 2e } //1 File Download Success.
		$a_01_3 = {42 44 5f 66 69 6c 65 5f 64 6f 77 6e 6c 6f 61 64 5f 70 61 74 68 } //1 BD_file_download_path
		$a_01_4 = {42 44 5f 66 69 6c 65 5f 66 75 6c 6c 5f 70 61 74 68 } //1 BD_file_full_path
		$a_01_5 = {42 44 5f 66 69 6c 65 5f 6e 61 6d 65 } //1 BD_file_name
		$a_01_6 = {64 6f 77 6e 6c 6f 61 64 2e 65 78 65 } //1 download.exe
		$a_81_7 = {41 6e 74 69 2d 56 69 72 75 73 } //1 Anti-Virus
		$a_81_8 = {2f 63 68 65 63 6b 65 72 } //1 /checker
		$a_81_9 = {74 65 73 74 66 69 6c 65 } //1 testfile
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}