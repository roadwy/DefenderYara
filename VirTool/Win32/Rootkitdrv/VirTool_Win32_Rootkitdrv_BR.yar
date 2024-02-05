
rule VirTool_Win32_Rootkitdrv_BR{
	meta:
		description = "VirTool:Win32/Rootkitdrv.BR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 } //01 00 
		$a_03_1 = {83 65 fc 00 53 56 57 be 00 10 00 00 68 44 64 6b 20 56 6a 00 ff 15 90 02 30 8b d8 81 fb 04 00 00 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}