
rule VirTool_Win64_BofSctskrun_A{
	meta:
		description = "VirTool:Win64/BofSctskrun.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 20 54 61 73 6b 20 53 63 68 65 64 75 6c 65 72 20 69 6e 74 65 72 66 61 63 65 } //1 create Task Scheduler interface
		$a_01_1 = {53 79 73 41 6c 6c 6f 63 53 74 72 69 6e 67 } //1 SysAllocString
		$a_01_2 = {67 65 74 20 74 68 65 20 72 6f 6f 74 20 66 6f 6c 64 65 72 } //1 get the root folder
		$a_01_3 = {72 75 6e 20 74 68 65 20 74 61 73 6b } //1 run the task
		$a_01_4 = {73 74 6f 70 20 74 68 65 20 74 61 73 6b } //1 stop the task
		$a_01_5 = {72 75 6e 20 74 61 73 6b 20 72 65 74 75 72 6e 65 64 } //1 run task returned
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}