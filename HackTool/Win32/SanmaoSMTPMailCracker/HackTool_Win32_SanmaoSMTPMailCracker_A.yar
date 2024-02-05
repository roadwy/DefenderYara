
rule HackTool_Win32_SanmaoSMTPMailCracker_A{
	meta:
		description = "HackTool:Win32/SanmaoSMTPMailCracker.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 61 00 6e 00 6d 00 61 00 6f 00 20 00 53 00 4d 00 54 00 50 00 20 00 4d 00 61 00 69 00 6c 00 20 00 43 00 72 00 61 00 63 00 6b 00 65 00 72 00 } //01 00 
		$a_01_1 = {45 48 4c 4f 20 79 6c 6d 66 2d 70 63 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}