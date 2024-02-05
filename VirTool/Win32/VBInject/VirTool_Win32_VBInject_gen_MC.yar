
rule VirTool_Win32_VBInject_gen_MC{
	meta:
		description = "VirTool:Win32/VBInject.gen!MC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {fb 12 fc 0d 04 90 01 02 fc 22 80 90 01 02 fc a0 90 00 } //02 00 
		$a_03_1 = {4a f5 b8 0b 00 00 db 1c 90 01 01 00 6c 70 ff 6c 6c ff 2a 31 70 ff f5 00 00 00 00 90 00 } //01 00 
		$a_03_2 = {6b 72 ff e7 80 10 00 4a c2 f5 01 00 00 00 aa 6c 10 00 4d 5c ff 08 40 04 90 01 02 0a 90 01 01 00 10 00 90 00 } //01 00 
		$a_03_3 = {80 0c 00 2e 90 01 01 ff 40 5e 90 01 01 00 04 00 71 90 01 01 ff 2d 90 01 01 ff f5 00 00 00 00 f5 00 00 00 00 6c 90 01 01 ff 6c 90 01 01 ff 6c 90 01 01 ff 0a 90 01 01 00 14 00 90 03 02 01 3c 14 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}