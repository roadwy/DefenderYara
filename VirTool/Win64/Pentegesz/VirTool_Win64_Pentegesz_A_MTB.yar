
rule VirTool_Win64_Pentegesz_A_MTB{
	meta:
		description = "VirTool:Win64/Pentegesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {53 65 74 75 70 50 65 72 73 69 73 74 65 6e 63 65 } //1 SetupPersistence
		$a_81_1 = {29 2e 52 65 71 75 65 73 74 43 6f 6d 6d 61 6e 64 } //1 ).RequestCommand
		$a_81_2 = {29 2e 4d 69 64 64 6c 65 77 61 72 65 } //1 ).Middleware
		$a_81_3 = {29 2e 43 72 65 61 74 65 46 6f 72 6d 46 69 6c 65 } //1 ).CreateFormFile
		$a_81_4 = {29 2e 55 70 6c 6f 61 64 46 69 6c 65 } //1 ).UploadFile
		$a_81_5 = {29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 ).DownloadFile
		$a_81_6 = {29 2e 45 78 65 63 41 6e 64 47 65 74 4f 75 74 70 75 74 } //1 ).ExecAndGetOutput
		$a_81_7 = {29 2e 48 6f 73 74 6e 61 6d 65 } //1 ).Hostname
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}