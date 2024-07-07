
rule VirTool_Win32_VBInject_AHS_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHS!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb 58 8b ec 83 4b 4b 4b 39 18 75 ee bb ef 0c 56 8d 4b 4b 4b 39 58 04 75 e1 31 db 53 53 53 54 6a 03 81 04 24 90 01 03 00 52 51 54 ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}