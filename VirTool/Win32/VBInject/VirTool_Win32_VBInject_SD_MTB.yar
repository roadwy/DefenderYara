
rule VirTool_Win32_VBInject_SD_MTB{
	meta:
		description = "VirTool:Win32/VBInject.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 ff d9 d0 d9 d0 d9 d0 d9 d0 d9 d0 75 90 0a 50 00 ff 34 38 90 02 10 5a 90 02 10 e8 90 01 01 fe ff ff 90 02 10 52 90 00 } //1
		$a_03_1 = {64 0b 05 30 00 00 00 90 02 10 e9 90 0a 25 00 31 c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}