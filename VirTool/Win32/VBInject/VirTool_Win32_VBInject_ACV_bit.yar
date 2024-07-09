
rule VirTool_Win32_VBInject_ACV_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACV!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb 57 8b ec 83 4b 4b 39 18 75 ?? bb ee 0c 56 8d 4b 4b 39 58 04 75 ?? 31 db 53 53 53 54 6a 02 81 04 24 fe 4f 04 00 52 51 54 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}