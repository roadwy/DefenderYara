
rule VirTool_Win32_VBInject_AHX_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {ad 83 f8 00 74 fa bb 59 8b ec 83 4b 4b 4b 4b 39 18 75 ed bb ef 0c 56 8d 4b 4b 4b 39 58 04 75 e0 31 db 53 53 53 54 6a 03 81 04 24 fd 4f 04 00 52 51 54 ff d0 } //2
		$a_03_1 = {59 89 c7 51 f3 a4 59 6a 00 e8 ?? ?? ?? 00 7d f7 ff e0 90 09 06 00 5e 68 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}