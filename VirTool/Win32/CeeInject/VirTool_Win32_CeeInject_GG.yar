
rule VirTool_Win32_CeeInject_GG{
	meta:
		description = "VirTool:Win32/CeeInject.GG,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb fe 55 8b ec 81 ec 90 04 01 03 70 2d 8f 00 00 00 56 90 00 } //1
		$a_03_1 = {ff ff d0 8d 85 90 04 01 03 70 2d 8f ff ff ff ff d0 8d 85 90 04 01 03 70 2d 8f ff ff ff ff d0 8d 85 90 04 01 03 70 2d 8f ff ff ff ff d0 90 02 80 8d 85 90 04 01 03 70 2d 8f ff ff ff ff d0 4e 75 90 04 01 03 80 2d bf 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}