
rule VirTool_WinNT_He4Hook{
	meta:
		description = "VirTool:WinNT/He4Hook,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 c0 a3 68 7b 01 00 0f 84 a2 00 00 00 fa a1 b4 03 01 00 8b 08 89 0d 6c 7b 01 00 8b 48 04 89 0d 70 7b 01 00 8b 0e c7 05 00 7b 01 00 3e 50 01 00 89 08 8b 4e 04 89 48 04 8b 0d 10 03 01 00 a1 70 03 01 00 8b 51 01 8b 30 8b 14 96 89 15 58 7b 01 00 8b 49 01 8b 00 c7 04 88 76 54 01 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule VirTool_WinNT_He4Hook_2{
	meta:
		description = "VirTool:WinNT/He4Hook,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 20 53 56 57 80 65 ec 00 a1 78 03 01 00 89 45 fc c7 45 f0 64 00 00 00 83 65 f4 00 a1 24 ba 01 00 83 e0 01 85 c0 0f 84 14 01 00 00 a1 e0 02 01 00 8b 40 01 8b 0d 40 03 01 00 8b 09 81 3c 81 7a 80 01 00 0f 85 f5 00 00 00 a1 84 03 01 00 8b 40 01 8b 0d 40 03 01 00 8b 09 81 3c 81 b4 80 01 00 0f 85 d8 00 00 00 a1 80 03 01 00 8b 40 01 8b 0d 40 03 01 00 8b 09 81 3c 81 ea 80 01 00 0f 85 bb 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}