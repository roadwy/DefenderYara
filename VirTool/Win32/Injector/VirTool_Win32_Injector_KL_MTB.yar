
rule VirTool_Win32_Injector_KL_MTB{
	meta:
		description = "VirTool:Win32/Injector.KL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 03 45 f0 73 90 01 01 e8 90 01 04 8a 00 88 45 f7 8b 45 f0 89 45 f8 90 01 02 80 75 f7 90 01 01 90 01 02 8b 45 fc 03 45 f8 73 90 01 01 e8 90 01 04 8a 55 f7 88 10 90 01 01 ff 45 f0 81 7d f0 90 01 04 75 90 01 01 8b e5 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}