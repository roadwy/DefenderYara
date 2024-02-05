
rule HackTool_Win32_UACBypass_LKV_MTB{
	meta:
		description = "HackTool:Win32/UACBypass.LKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 73 63 73 69 63 70 6c 5f 62 79 70 61 73 73 55 41 43 2d 6d 61 69 6e 5c 44 65 62 75 67 5c 69 73 63 73 69 65 78 65 2e 70 64 62 } //01 00 
		$a_01_1 = {69 73 63 73 69 65 78 65 5f 6f 72 67 2e 53 65 72 76 69 63 65 4d 61 69 6e } //01 00 
		$a_01_2 = {69 73 63 73 69 65 78 65 5f 6f 72 67 2e 44 69 73 63 70 45 73 74 61 62 6c 69 73 68 53 65 72 76 69 63 65 4c 69 6e 6b 61 67 65 } //00 00 
	condition:
		any of ($a_*)
 
}