
rule VirTool_MacOS_Myrddin_GV_MTB{
	meta:
		description = "VirTool:MacOS/Myrddin.GV!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 65 78 65 63 2f 65 78 65 63 5f 75 6e 69 78 2e 67 6f } //1 /exec/exec_unix.go
		$a_01_1 = {2f 4e 65 30 6e 64 30 67 2f 6d 65 72 6c 69 6e 2f } //1 /Ne0nd0g/merlin/
		$a_01_2 = {2f 63 6f 6d 6d 61 6e 64 73 2e 45 78 65 63 75 74 65 53 68 65 6c 6c 63 6f 64 65 51 75 65 75 65 55 73 65 72 41 50 43 } //1 /commands.ExecuteShellcodeQueueUserAPC
		$a_01_3 = {2f 63 6f 6d 6d 61 6e 64 73 2f 73 68 65 6c 6c 5f 64 61 72 77 69 6e 2e 67 6f } //1 /commands/shell_darwin.go
		$a_01_4 = {2f 75 73 72 2f 6c 6f 63 61 6c 2f 67 6f 2f 73 72 63 2f 6f 73 2f 65 78 65 63 75 74 61 62 6c 65 5f 64 61 72 77 69 6e 2e 67 6f } //1 /usr/local/go/src/os/executable_darwin.go
		$a_01_5 = {6d 79 74 68 69 63 2e 54 61 73 6b } //1 mythic.Task
		$a_01_6 = {53 65 6e 64 4d 65 72 6c 69 6e 4d 65 73 73 61 67 65 } //1 SendMerlinMessage
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}