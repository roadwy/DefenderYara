
rule HackTool_Win32_ElecFish_A_dha{
	meta:
		description = "HackTool:Win32/ElecFish.A!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 43 47 43 5f 4c 4f 47 20 3d 3d 3d 3e 20 52 65 63 65 69 76 65 20 4d 61 6b 65 20 53 65 73 73 69 6f 6e 20 46 72 61 6d 65 20 52 65 6d 6f 74 65 53 65 73 73 69 6f 6e 49 44 } //01 00 
		$a_01_1 = {4c 4c 47 43 5f 4c 4f 47 20 3d 3d 3d 3e 20 4d 61 6b 65 20 53 65 73 73 69 6f 6e 20 46 61 69 6c } //01 00 
		$a_01_2 = {4c 4c 47 43 5f 4c 4f 47 20 3d 3d 3d 3e 20 52 65 6d 6f 74 65 20 53 65 73 73 69 6f 6e 20 44 69 73 63 6f 6e 6e 65 63 74 65 64 } //01 00 
		$a_01_3 = {43 43 47 43 4c 4f 47 20 3d 3d 3d 3e 20 74 72 79 20 63 6f 6e 6e 65 63 74 20 74 6f 20 25 73 3a 25 64 } //00 00 
	condition:
		any of ($a_*)
 
}