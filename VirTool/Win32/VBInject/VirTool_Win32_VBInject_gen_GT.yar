
rule VirTool_Win32_VBInject_gen_GT{
	meta:
		description = "VirTool:Win32/VBInject.gen!GT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 bb db fb c7 80 90 01 04 3e 37 f2 3c 90 00 } //01 00 
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 4a 4f 4b 45 52 2d 56 41 49 4f 5c 4a 6f 6b 65 72 32 5c 56 42 36 2e 4f 4c 42 } //01 00  C:\Program Files (x86)\JOKER-VAIO\Joker2\VB6.OLB
		$a_03_2 = {8b 1e 8d 85 90 01 04 50 68 b0 00 00 00 ff b5 90 01 04 e8 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}