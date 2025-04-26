
rule VirTool_Win32_DelfInject_AD{
	meta:
		description = "VirTool:Win32/DelfInject.AD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 54 4d 65 6d 6f 72 79 4c 6f 61 64 4c 69 62 61 72 79 } //1 BTMemoryLoadLibary
		$a_01_1 = {52 70 65 00 45 78 65 63 75 74 65 46 72 6f 6d 4d 65 6d 00 00 4d 65 74 61 6c } //1
		$a_01_2 = {ff 46 0c 8b 45 f8 8b 08 85 c9 74 12 8b c1 33 d2 52 50 8b 46 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}