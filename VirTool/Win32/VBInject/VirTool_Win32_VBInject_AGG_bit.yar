
rule VirTool_Win32_VBInject_AGG_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 ff 30 46 5b 31 f3 3b 9c ?? ?? ?? 00 00 75 f1 } //2
		$a_03_1 = {0b 0c 1e 60 [0-20] 61 31 c1 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}