
rule VirTool_WinNT_Knockex_B{
	meta:
		description = "VirTool:WinNT/Knockex.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 c4 fc fa 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 ff 35 } //2
		$a_01_1 = {83 c4 04 ff 64 24 fc 50 fa 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 } //2
		$a_01_2 = {ff 75 08 58 66 81 38 ff 25 75 07 ff 70 02 58 ff 30 } //2
		$a_01_3 = {8b 45 08 3d 73 33 31 00 } //1
		$a_01_4 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}