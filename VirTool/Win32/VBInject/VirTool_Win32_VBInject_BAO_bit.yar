
rule VirTool_Win32_VBInject_BAO_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAO!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 53 8b ec 83 90 02 30 5b 90 02 30 43 90 02 30 43 90 02 30 be 00 10 40 00 90 02 30 ad 90 02 30 83 f8 00 90 02 30 74 90 02 30 39 18 90 02 30 75 90 02 30 57 90 02 30 bf eb 0c 56 8d 90 02 30 47 90 02 30 39 78 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}