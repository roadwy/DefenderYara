
rule Backdoor_Win32_Mansys{
	meta:
		description = "Backdoor:Win32/Mansys,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 72 76 69 63 65 4d 61 69 6e 00 53 74 61 72 74 4c 6f 6f 70 52 75 6e 44 6f 6f 72 } //1 敓癲捩䵥楡n瑓牡䱴潯剰湵潄牯
		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
		$a_01_2 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
		$a_01_3 = {53 79 73 4d 67 72 5c 4c 6f 61 64 65 72 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62 } //1 SysMgr\Loader\Release\Loader.pdb
		$a_01_4 = {47 6c 6f 62 61 6c 5c 72 75 6e 73 69 6e 67 6c 65 6f 62 6a 65 63 74 } //1 Global\runsingleobject
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}