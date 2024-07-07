
rule VirTool_Win32_Ninject_H{
	meta:
		description = "VirTool:Win32/Ninject.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {99 f7 fe 88 44 0d 90 01 01 0f bf 90 02 18 99 f7 90 00 } //1
		$a_03_1 = {8a 04 0a 30 84 2b 90 02 0a 99 f7 90 00 } //1
		$a_03_2 = {32 0c 02 88 90 01 05 88 0f 90 02 0a 99 f7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}