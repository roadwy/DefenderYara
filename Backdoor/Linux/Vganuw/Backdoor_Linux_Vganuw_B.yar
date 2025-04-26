
rule Backdoor_Linux_Vganuw_B{
	meta:
		description = "Backdoor:Linux/Vganuw.B,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6e 2e 48 61 6e 64 6c 65 52 75 6e 50 72 6f 63 65 73 73 } //1 main.HandleRunProcess
		$a_00_1 = {6d 61 69 6e 2e 48 61 6e 64 6c 65 44 65 6c 65 74 65 46 69 6c 65 } //1 main.HandleDeleteFile
		$a_00_2 = {6d 61 69 6e 2e 48 61 6e 64 6c 65 55 70 6c 6f 61 64 } //1 main.HandleUpload
		$a_00_3 = {6d 61 69 6e 2e 48 61 6e 64 6c 65 46 69 6c 65 4d 61 6e 61 67 65 72 } //1 main.HandleFileManager
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}