
rule VirTool_Win64_BofSctskcreate_A{
	meta:
		description = "VirTool:Win64/BofSctskcreate.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 20 74 68 65 20 72 6f 6f 74 20 66 6f 6c 64 65 72 } //1 get the root folder
		$a_01_1 = {47 6f 74 20 75 73 65 72 20 6e 61 6d 65 20 61 6e 64 20 73 65 63 75 72 69 74 79 20 64 65 73 63 72 69 70 74 6f 72 } //1 Got user name and security descriptor
		$a_01_2 = {54 61 73 6b 20 61 6c 72 65 61 64 79 20 65 78 69 73 74 73 } //1 Task already exists
		$a_01_3 = {52 65 67 69 73 74 65 72 65 64 20 74 61 73 6b } //1 Registered task
		$a_01_4 = {43 72 65 61 74 65 64 20 74 61 73 6b 20 70 61 74 68 } //1 Created task path
		$a_01_5 = {63 72 65 61 74 65 54 61 73 6b 20 68 6f 73 74 6e 61 6d 65 } //1 createTask hostname
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}