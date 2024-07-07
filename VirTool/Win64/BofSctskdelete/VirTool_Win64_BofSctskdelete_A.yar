
rule VirTool_Win64_BofSctskdelete_A{
	meta:
		description = "VirTool:Win64/BofSctskdelete.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 20 74 68 65 20 72 6f 6f 74 20 66 6f 6c 64 65 72 } //1 get the root folder
		$a_01_1 = {64 65 6c 65 74 65 20 74 68 65 20 72 65 71 75 65 73 74 65 64 20 74 61 73 6b 20 66 6f 6c 64 65 72 } //1 delete the requested task folder
		$a_01_2 = {73 74 6f 70 20 74 68 65 20 74 61 73 6b } //1 stop the task
		$a_01_3 = {44 65 6c 65 74 65 64 20 74 68 65 20 74 61 73 6b } //1 Deleted the task
		$a_01_4 = {64 65 6c 65 74 65 54 61 73 6b 20 66 61 69 6c 65 64 } //1 deleteTask failed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}