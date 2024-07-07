
rule VirTool_Win32_VBInject_EW{
	meta:
		description = "VirTool:Win32/VBInject.EW,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 61 6d 53 74 65 61 6c 65 72 00 } //1
		$a_01_1 = {56 00 69 00 63 00 74 00 69 00 6d 00 20 00 45 00 6d 00 61 00 69 00 6c 00 20 00 2e 00 2e 00 00 00 } //1
		$a_00_2 = {ff 15 24 10 40 00 8d 55 9c 8d 45 ac 52 8d 4d bc 50 8d 55 cc 51 52 eb 41 8d 55 8c 8d 4d cc c7 45 94 80 af 40 00 c7 45 8c 08 00 00 00 ff 15 7c 10 40 00 } //1
		$a_00_3 = {83 c4 18 b9 04 00 02 80 b8 0a 00 00 00 66 3b f3 89 4d a4 89 45 9c 89 4d b4 89 45 ac 89 4d c4 89 45 bc 74 43 8d 55 8c 8d 4d cc c7 45 94 30 af 40 00 c7 45 8c 08 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}