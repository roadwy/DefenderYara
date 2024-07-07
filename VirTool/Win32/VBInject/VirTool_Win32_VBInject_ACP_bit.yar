
rule VirTool_Win32_VBInject_ACP_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACP!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 db 81 cb 54 8b ec 83 43 52 be 00 10 40 00 ad 83 f8 00 74 90 01 01 39 18 75 90 01 01 ba ea 0c 56 8d 42 42 39 50 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}