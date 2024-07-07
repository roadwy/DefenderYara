
rule Backdoor_Win32_Redsip_A{
	meta:
		description = "Backdoor:Win32/Redsip.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 00 4d 00 44 00 5f 00 46 00 69 00 6c 00 65 00 5f 00 52 00 55 00 4e 00 5f 00 48 00 49 00 44 00 45 00 } //1 CMD_File_RUN_HIDE
		$a_01_1 = {43 00 4d 00 44 00 5f 00 46 00 49 00 4c 00 45 00 5f 00 55 00 50 00 4c 00 4f 00 41 00 44 00 } //1 CMD_FILE_UPLOAD
		$a_01_2 = {43 00 4d 00 44 00 5f 00 46 00 69 00 6c 00 65 00 5f 00 46 00 49 00 4e 00 44 00 } //1 CMD_File_FIND
		$a_01_3 = {53 00 48 00 45 00 4c 00 4c 00 5f 00 43 00 4d 00 44 00 } //1 SHELL_CMD
		$a_01_4 = {50 00 72 00 6f 00 63 00 46 00 69 00 6c 00 65 00 55 00 70 00 6c 00 6f 00 61 00 64 00 } //1 ProcFileUpload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}