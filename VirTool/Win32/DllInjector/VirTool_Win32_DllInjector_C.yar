
rule VirTool_Win32_DllInjector_C{
	meta:
		description = "VirTool:Win32/DllInjector.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00 } //1 刀晥敬瑣癩䱥慯敤r
		$a_01_1 = {81 f9 5b bc 4a 6a 0f 85 } //1
		$a_03_2 = {8e 4e 0e ec 74 ?? ?? ?? ?? aa fc 0d 7c 74 ?? ?? ?? ?? 54 ca af 91 74 ?? ?? ?? ?? ef ce e0 60 } //1
		$a_03_3 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00 } //1
		$a_01_4 = {b8 0a 4c 53 75 } //1
		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 40 [0-10] ff d5 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}