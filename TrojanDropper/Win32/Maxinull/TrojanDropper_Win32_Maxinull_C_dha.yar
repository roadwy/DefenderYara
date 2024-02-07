
rule TrojanDropper_Win32_Maxinull_C_dha{
	meta:
		description = "TrojanDropper:Win32/Maxinull.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 73 66 62 75 66 51 73 70 64 66 74 74 42 } //01 00  DsfbufQspdfttB
		$a_01_1 = {58 69 53 39 32 42 66 4f 58 6f 79 52 70 35 56 36 39 33 32 4d } //01 00  XiS92BfOXoyRp5V6932M
		$a_01_2 = {64 6e 65 2f 66 79 66 } //01 00  dne/fyf
		$a_01_3 = {3c 21 2d 2d 20 69 20 2d 2d 3e } //01 00  <!-- i -->
		$a_01_4 = {69 00 6d 00 61 00 67 00 65 00 2f 00 78 00 2d 00 78 00 62 00 69 00 74 00 6d 00 61 00 70 00 } //01 00  image/x-xbitmap
		$a_01_5 = {50 00 72 00 6f 00 78 00 79 00 4f 00 76 00 65 00 72 00 72 00 69 00 64 00 65 00 } //00 00  ProxyOverride
	condition:
		any of ($a_*)
 
}