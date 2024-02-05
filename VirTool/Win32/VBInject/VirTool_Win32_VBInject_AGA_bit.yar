
rule VirTool_Win32_VBInject_AGA_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGA!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {a6 f3 55 89 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 00 } //01 00 
		$a_03_1 = {a6 f3 89 e5 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 00 } //01 00 
		$a_03_2 = {a6 f3 54 0d eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 00 } //01 00 
		$a_03_3 = {a6 f3 89 54 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 00 } //01 00 
		$a_03_4 = {a6 f3 31 c1 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 00 } //01 00 
		$a_03_5 = {a6 f3 c1 39 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 00 } //01 00 
		$a_03_6 = {a6 f3 39 d9 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 00 } //01 00 
		$a_03_7 = {a6 f3 d9 0f eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 01 02 eb f5 90 01 02 00 00 6c 74 ff a6 f3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}