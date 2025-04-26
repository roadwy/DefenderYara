
rule Backdoor_Win32_Choopla_D_dha{
	meta:
		description = "Backdoor:Win32/Choopla.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 5f 47 65 74 5f 4c 6f 63 61 6c 44 69 72 65 63 74 6f 72 79 5f 61 6e 64 5f 41 6c 6c 44 69 72 76 65 73 } //3 A_Get_LocalDirectory_and_AllDirves
		$a_01_1 = {48 5f 43 6f 70 79 46 69 6c 65 } //2 H_CopyFile
		$a_01_2 = {47 5f 55 70 6c 6f 61 64 46 69 6c 65 } //2 G_UploadFile
		$a_01_3 = {4a 5f 43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 } //2 J_CreateDirectory
		$a_01_4 = {53 45 4c 45 43 54 20 5b 6e 61 6d 65 5d 20 46 52 4f 4d 20 6d 61 73 74 65 72 2e 64 62 6f 2e 73 79 73 64 61 74 61 62 61 73 65 73 20 4f 52 44 45 52 20 42 59 20 31 } //1 SELECT [name] FROM master.dbo.sysdatabases ORDER BY 1
		$a_01_5 = {43 6f 70 79 46 69 6c 65 5f 41 6e 64 5f 44 69 72 65 63 74 6f 72 79 } //1 CopyFile_And_Directory
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}