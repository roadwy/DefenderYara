
rule VirTool_Win32_Obfuscator_AIB{
	meta:
		description = "VirTool:Win32/Obfuscator.AIB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 6f 64 65 64 20 62 79 20 42 52 49 41 4e 20 4b 52 45 42 53 20 66 6f 72 20 70 65 72 73 6f 6e 61 6c 20 75 73 65 20 6f 6e 6c 79 2e 20 49 20 6c 6f 76 65 20 6d 79 20 6a 6f 62 } //00 00  Coded by BRIAN KREBS for personal use only. I love my job
		$a_01_1 = {00 5d 04 00 00 b8 08 03 80 5c } //22 00 
	condition:
		any of ($a_*)
 
}