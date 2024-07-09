
rule VirTool_Win32_DelfInject_AB{
	meta:
		description = "VirTool:Win32/DelfInject.AB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 50 45 } //1 RunPE
		$a_03_1 = {07 00 01 00 90 09 06 00 c7 85 } //1
		$a_01_2 = {8a 54 1f ff 0f b7 ce c1 e9 08 32 d1 88 54 18 ff 33 c0 8a 44 1f ff 66 03 f0 66 69 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}