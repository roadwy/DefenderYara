
rule VirTool_Win32_VBInject_SF_MTB{
	meta:
		description = "VirTool:Win32/VBInject.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 07 bb 01 00 00 00 eb 02 33 db 90 05 0a 01 90 8b 45 fc 03 45 f4 90 05 0a 01 90 85 db 75 90 01 01 90 05 0a 01 90 8a 16 90 05 0a 01 90 80 f2 90 01 01 88 55 fb 90 05 0a 01 90 8a 55 fb 88 10 90 05 0a 01 90 8d 45 f4 e8 90 01 04 90 05 0a 01 90 46 4f 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}