
rule HackTool_Win64_Blueflower_B{
	meta:
		description = "HackTool:Win64/Blueflower.B,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 2d 70 6c 65 68 } //01 00  --pleh
		$a_01_1 = {5b 45 58 45 5d 20 44 75 6d 70 69 6e 67 20 70 61 73 73 77 6f 72 64 73 00 5b 45 58 45 5d 20 45 78 69 74 69 6e 67 } //01 00 
		$a_01_2 = {2d 6c 20 3a 20 73 70 65 63 69 66 79 20 6c 73 61 20 66 69 6c 65 6e 61 6d 65 } //01 00  -l : specify lsa filename
		$a_01_3 = {2d 75 20 3a 20 73 70 65 63 69 66 79 20 75 73 65 72 20 77 68 6f 73 65 20 70 61 73 73 77 6f 72 64 20 69 73 20 74 6f 20 62 65 20 72 65 74 72 69 65 76 65 64 } //00 00  -u : specify user whose password is to be retrieved
		$a_01_4 = {00 5d 04 00 } //00 8a 
	condition:
		any of ($a_*)
 
}