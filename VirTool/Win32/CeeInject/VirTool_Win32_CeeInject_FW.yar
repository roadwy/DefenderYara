
rule VirTool_Win32_CeeInject_FW{
	meta:
		description = "VirTool:Win32/CeeInject.FW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 68 6f 78 6f 74 69 63 53 69 67 6e } //1 ChoxoticSign
		$a_01_1 = {b0 4b 35 f7 20 87 21 92 73 65 40 48 54 f5 34 c7 0c 6e 23 26 a4 c5 02 1c 4a 7e 14 70 f7 c3 ad b0 4e b3 3c 26 c6 fc 88 08 0b ac 3a ef a2 44 9c 8a } //1
		$a_03_2 = {8a 00 31 d0 88 01 83 45 90 01 01 02 83 55 90 01 01 00 8b 85 90 01 04 8b 55 90 01 01 89 d3 31 c3 8b 85 90 01 04 8b 55 90 01 01 89 d6 31 c6 89 d8 09 f0 85 c0 0f 95 c0 84 c0 90 00 } //1
		$a_03_3 = {89 c7 81 e7 ff 03 00 00 0f b6 bc 3d 90 01 04 89 fb 30 19 83 c0 02 83 d2 00 83 c1 02 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}