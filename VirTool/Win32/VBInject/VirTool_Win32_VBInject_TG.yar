
rule VirTool_Win32_VBInject_TG{
	meta:
		description = "VirTool:Win32/VBInject.TG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {ff d6 6a 35 ff d7 8b d0 8d 8d b0 fe ff ff ff d6 68 a0 00 00 00 ff d7 8b d0 } //2
		$a_00_1 = {5c 00 4b 00 61 00 64 00 61 00 62 00 72 00 5c 00 41 00 6c 00 61 00 6b 00 61 00 } //1 \Kadabr\Alaka
		$a_02_2 = {5c 00 62 00 72 00 61 00 4b 00 61 00 [0-10] 41 00 6c 00 61 00 2e 00 76 00 62 00 70 00 } //1
		$a_00_3 = {45 00 73 00 74 00 61 00 62 00 6c 00 65 00 63 00 65 00 72 00 } //1 Establecer
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}