
rule VirTool_Win32_VBInject_ACI_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACI!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {bf 00 00 53 00 [0-30] 83 c7 4d } //1
		$a_03_1 = {39 3b 0f 85 ?? ?? ff ff [0-30] 81 7b 04 56 00 42 00 0f 85 } //1
		$a_03_2 = {81 78 04 ec 0c 56 8d 0f 85 ?? ?? ff ff 5b 31 db 53 53 53 54 6a 00 81 04 24 00 00 04 00 52 51 54 ff d0 } //1
		$a_03_3 = {ff 34 0e 5b 81 f3 ?? ?? ?? ?? 53 8f 04 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}