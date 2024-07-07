
rule VirTool_Win64_Remetecez_B_MTB{
	meta:
		description = "VirTool:Win64/Remetecez.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 56 57 55 54 58 66 83 e4 f0 50 6a 60 5a 68 63 6d 64 00 54 59 48 29 d4 65 48 8b 32 48 8b 76 18 48 8b 76 10 48 ad 48 8b 30 48 8b 7e 30 03 57 3c 8b 5c 17 28 8b 74 1f 20 48 01 fe 8b 54 1f 24 } //1
		$a_03_1 = {48 bb bb bb bb bb bb bb bb bb 48 b9 cc cc cc cc cc cc cc cc 48 89 0b 48 83 ec 50 48 89 d9 48 c7 c2 00 04 00 00 41 b8 02 00 00 00 90 01 05 48 b8 bb bb bb bb bb bb bb bb 90 01 07 48 83 c4 50 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}