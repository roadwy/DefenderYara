
rule VirTool_Win32_VBInject_DN{
	meta:
		description = "VirTool:Win32/VBInject.DN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {f5 fe 00 00 00 c2 04 60 ff 9d e7 aa 04 60 ff 9d fb 12 } //01 00 
		$a_03_1 = {e7 f5 4d 5a 00 00 cc 1c 90 01 02 ff 90 00 } //01 00 
		$a_03_2 = {f5 50 45 00 00 cc 1c 90 01 02 ff 90 00 } //01 00 
		$a_03_3 = {f5 2a 00 00 00 0b 90 01 01 00 04 00 23 90 01 02 2a 23 90 01 02 f5 56 00 00 00 0b 90 01 01 00 04 00 23 90 01 02 2a 23 90 01 02 f5 4d 00 00 00 0b 90 01 01 00 04 00 23 90 01 02 2a 23 90 01 02 f5 57 90 00 } //01 00 
		$a_03_4 = {f3 e8 00 2b 90 01 02 6c 90 01 01 ff 90 00 } //01 00 
		$a_03_5 = {bc 02 f5 f8 00 00 00 aa f5 28 00 00 00 08 08 00 8a 90 01 02 b2 aa 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}