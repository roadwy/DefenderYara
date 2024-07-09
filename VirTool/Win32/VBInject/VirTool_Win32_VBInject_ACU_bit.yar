
rule VirTool_Win32_VBInject_ACU_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACU!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb 59 8b ec 83 66 83 eb 04 39 18 75 ?? bb ef 0c 56 8d 4b 4b 4b 39 58 04 75 ?? 31 db 53 53 53 54 68 ?? ?? ?? ?? 52 51 54 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}