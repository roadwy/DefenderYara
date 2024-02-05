
rule HackTool_Win32_Rdpbrute_gen_B{
	meta:
		description = "HackTool:Win32/Rdpbrute.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {50 4f 52 54 20 33 33 38 39 20 6f 70 65 6e 20 25 73 0a } //02 00 
		$a_01_1 = {46 6f 75 6e 64 20 52 44 50 20 25 73 } //01 00 
		$a_01_2 = {53 74 61 72 74 69 6e 67 20 66 74 70 20 62 72 75 74 65 20 25 73 0a } //01 00 
		$a_01_3 = {44 69 61 70 61 73 6f 6e 20 44 61 74 61 20 73 65 6e 74 0a } //01 00 
		$a_01_4 = {43 20 25 73 20 2d 20 25 73 0a } //00 00 
	condition:
		any of ($a_*)
 
}