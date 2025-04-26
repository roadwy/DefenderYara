
rule MonitoringTool_Win32_Csysserv{
	meta:
		description = "MonitoringTool:Win32/Csysserv,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 4b 65 79 50 72 6f 63 00 4d 6f 75 73 65 50 72 6f 63 00 53 65 74 56 61 6c 75 65 73 4b 65 79 00 53 65 74 56 61 6c 75 65 73 4d 6f 75 73 65 } //10 搮汬䬀祥牐捯䴀畯敳牐捯匀瑥慖畬獥敋y敓噴污敵䵳畯敳
		$a_01_1 = {3d a0 86 01 00 } //2
		$a_01_2 = {81 78 04 a0 86 01 00 } //2
		$a_01_3 = {47 6c 6f 62 61 6c 5c 4b 65 79 4c 6f 67 4d 74 78 } //2 Global\KeyLogMtx
		$a_01_4 = {47 6c 6f 62 61 6c 5c 4d 4d 46 53 68 61 72 65 64 44 61 74 61 } //2 Global\MMFSharedData
		$a_01_5 = {4b 65 79 4c 6f 67 4d 74 78 } //1 KeyLogMtx
		$a_01_6 = {4d 4d 46 53 68 61 72 65 64 44 61 74 61 } //1 MMFSharedData
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=15
 
}
rule MonitoringTool_Win32_Csysserv_2{
	meta:
		description = "MonitoringTool:Win32/Csysserv,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 47 6c 6f 62 61 6c 5c 4b 65 79 4c 6f 67 4d 74 78 00 00 } //1
		$a_01_1 = {4b 65 79 50 72 6f 63 00 54 68 65 48 6f 6f 6b 58 50 2e 64 6c 6c } //1
		$a_01_2 = {53 65 74 56 61 6c 75 65 73 4d 6f 75 73 65 } //1 SetValuesMouse
		$a_01_3 = {53 65 74 56 61 6c 75 65 73 4b 65 79 } //1 SetValuesKey
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule MonitoringTool_Win32_Csysserv_3{
	meta:
		description = "MonitoringTool:Win32/Csysserv,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 45 47 75 61 72 64 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //2
		$a_01_1 = {31 42 37 37 44 33 30 41 2d 38 31 43 39 2d 34 39 37 41 2d 38 36 34 37 2d 31 34 32 46 37 35 31 31 42 31 46 42 } //1 1B77D30A-81C9-497A-8647-142F7511B1FB
		$a_01_2 = {49 45 47 75 61 72 64 2e 49 45 57 65 62 47 75 61 72 64 2e 31 } //1 IEGuard.IEWebGuard.1
		$a_01_3 = {73 20 27 7b 35 41 42 30 44 32 36 36 2d 44 44 32 42 2d 34 30 30 36 2d 42 39 44 36 2d 41 39 31 34 35 32 39 31 42 44 44 36 } //1 s '{5AB0D266-DD2B-4006-B9D6-A9145291BDD6
		$a_01_4 = {49 45 57 65 62 47 43 55 53 54 4f 4d 5f } //1 IEWebGCUSTOM_
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}