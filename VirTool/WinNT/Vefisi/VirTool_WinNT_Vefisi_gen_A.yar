
rule VirTool_WinNT_Vefisi_gen_A{
	meta:
		description = "VirTool:WinNT/Vefisi.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 08 00 00 "
		
	strings :
		$a_01_0 = {bb 44 64 6b 20 53 bf 00 02 00 00 57 6a 01 ff d6 8b 4d 10 80 21 00 ff 75 08 80 20 00 89 45 fc } //1
		$a_01_1 = {8b 5c 24 08 56 8b c3 57 8d 50 01 8a 08 40 84 c9 75 f9 8b 7c 24 18 57 ff 74 24 18 2b c2 8d 34 18 56 } //1
		$a_01_2 = {6b 69 6c 6c 00 00 00 6b 77 61 74 63 68 00 00 53 79 73 74 65 6d 00 55 8b ec 81 ec 1c 06 } //1
		$a_03_3 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 0d ?? ?? 01 00 8b 31 a1 ?? ?? 01 00 8b 50 01 8b 14 96 89 15 ?? ?? 01 00 8b 40 01 8b 09 c7 04 81 } //5
		$a_01_4 = {01 00 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //3
		$a_01_5 = {5a 77 51 75 65 72 79 44 69 72 65 63 74 6f 72 79 46 69 6c 65 } //2 ZwQueryDirectoryFile
		$a_01_6 = {5a 77 53 65 74 56 61 6c 75 65 4b 65 79 } //2 ZwSetValueKey
		$a_01_7 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //2 KeServiceDescriptorTable
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*5+(#a_01_4  & 1)*3+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=15
 
}