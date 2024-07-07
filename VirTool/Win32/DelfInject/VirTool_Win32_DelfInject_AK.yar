
rule VirTool_Win32_DelfInject_AK{
	meta:
		description = "VirTool:Win32/DelfInject.AK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 45 ec 50 6a 01 8d 45 df 50 8b 45 e0 03 c0 03 45 98 50 8b 45 c0 50 ff 15 90 01 04 39 90 01 01 39 90 01 01 39 90 01 01 c7 85 f4 fe ff ff 07 00 01 00 90 00 } //1
		$a_03_1 = {6a 40 68 00 30 00 00 8b 45 90 01 01 50 8b 43 34 50 8b 45 90 01 01 50 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}