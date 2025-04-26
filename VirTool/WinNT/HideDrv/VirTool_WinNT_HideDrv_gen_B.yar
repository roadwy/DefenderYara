
rule VirTool_WinNT_HideDrv_gen_B{
	meta:
		description = "VirTool:WinNT/HideDrv.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f b7 00 3d 93 08 00 00 74 ?? 3d 28 0a 00 00 74 } //1
		$a_03_1 = {01 00 fa 0f 20 c0 [0-10] 25 ff ff fe ff [0-10] 0f 22 c0 } //1
		$a_03_2 = {01 00 8b 00 8b 0d ?? ?? 01 00 c7 04 88 ?? ?? 01 00 a1 ?? ?? 01 00 8b 00 8b 0d ?? ?? 01 00 c7 04 88 ?? ?? 01 00 a1 ac [0-60] 0f 22 c0 } //1
		$a_01_3 = {b8 06 00 00 80 eb } //1
		$a_01_4 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}