
rule VirTool_Win32_CeeInject_LS_bit{
	meta:
		description = "VirTool:Win32/CeeInject.LS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 61 76 74 71 63 68 71 6d 6a 79 } //1 wavtqchqmjy
		$a_01_1 = {6e 79 7a 62 71 67 61 7a 66 7a 6b 64 66 61 } //1 nyzbqgazfzkdfa
		$a_01_2 = {29 c9 49 23 08 f8 83 d8 fc f7 d1 8d 49 e8 d1 c1 c1 c9 09 01 d1 f8 83 d1 ff 31 d2 4a 21 ca c1 c2 09 d1 ca } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}