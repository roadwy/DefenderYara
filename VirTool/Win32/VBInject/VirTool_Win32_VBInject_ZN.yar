
rule VirTool_Win32_VBInject_ZN{
	meta:
		description = "VirTool:Win32/VBInject.ZN,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 0e 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 80 dc 04 00 00 c1 cf 0d 03 8b 0d 90 01 04 c7 81 e0 04 00 00 f8 eb f4 3b 8b 15 90 01 04 c7 82 e4 04 00 00 7c 24 20 75 90 00 } //01 00 
		$a_03_1 = {c7 82 dc 04 00 00 c1 cf 0d 03 a1 90 01 04 c7 80 e0 04 00 00 f8 eb f4 3b 8b 0d 90 01 04 c7 81 e4 04 00 00 7c 24 20 75 90 00 } //01 00 
		$a_03_2 = {c7 82 dc 04 00 00 c1 cf 0d 03 8b 90 01 02 c7 81 e0 04 00 00 f8 eb f4 3b 8b 90 01 02 c7 82 e4 04 00 00 7c 24 20 75 90 00 } //01 00 
		$a_03_3 = {c7 82 dc 04 00 00 c1 cf 0d 03 8b 15 90 01 04 c7 82 e0 04 00 00 f8 eb f4 3b 8b 15 90 01 04 c7 82 e4 04 00 00 7c 24 20 75 90 00 } //01 00 
		$a_03_4 = {c7 04 f9 f8 eb f4 3b 8b 15 90 01 04 c7 44 fa 04 7c 24 20 75 90 00 } //01 00 
		$a_03_5 = {c7 80 dc 04 00 00 c1 cf 0d 03 8b 0d 90 01 04 c7 81 e0 04 00 00 f8 eb f4 3b a1 90 01 04 c7 80 e4 04 00 00 7c 24 20 75 90 00 } //01 00 
		$a_03_6 = {c7 80 dc 04 00 00 c1 cf 0d 03 a1 90 01 04 c7 80 e0 04 00 00 f8 eb f4 3b a1 90 01 04 c7 80 e4 04 00 00 7c 24 20 75 90 00 } //01 00 
		$a_03_7 = {c7 81 dc 04 00 00 c1 cf 0d 03 8b 90 01 02 c7 82 e0 04 00 00 f8 eb f4 3b 8b 90 01 02 c7 81 e4 04 00 00 7c 24 20 75 90 00 } //01 00 
		$a_03_8 = {c7 80 dc 04 00 00 c1 cf 0d 03 8b 90 01 05 c7 81 e0 04 00 00 f8 eb f4 3b a1 90 01 04 c7 80 e4 04 00 00 7c 24 20 75 90 00 } //01 00 
		$a_03_9 = {c7 81 dc 04 00 00 c1 cf 0d 03 8b 90 01 05 c7 82 e0 04 00 00 f8 eb f4 3b 8b 90 01 05 c7 81 e4 04 00 00 7c 24 20 75 90 00 } //01 00 
		$a_03_10 = {c7 82 dc 04 00 00 c1 cf 0d 03 8b 0d 90 01 04 c7 81 e0 04 00 00 f8 eb f4 3b 8b 15 90 01 04 c7 82 e4 04 00 00 7c 24 20 75 90 00 } //01 00 
		$a_03_11 = {c7 82 dc 04 00 00 c1 cf 0d 03 8b 0d 90 01 04 8b 3d 90 01 04 c7 81 e0 04 00 00 f8 eb f4 3b 8b 15 90 01 04 c7 82 e4 04 00 00 7c 24 20 75 90 00 } //01 00 
		$a_03_12 = {c7 81 dc 04 00 00 c1 cf 0d 03 8b 0d 90 01 04 c7 81 e0 04 00 00 f8 eb f4 3b 8b 0d 90 01 04 c7 81 e4 04 00 00 7c 24 20 75 90 00 } //01 00 
		$a_03_13 = {c7 83 dc 04 00 00 c1 cf 0d 03 8b 1d 90 01 04 c7 83 e0 04 00 00 f8 eb f4 3b 8b 1d 90 01 04 c7 83 e4 04 00 00 7c 24 20 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}