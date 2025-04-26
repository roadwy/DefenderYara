
rule VirTool_WinNT_Rootkit_A{
	meta:
		description = "VirTool:WinNT/Rootkit.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {61 67 6f 6e 79 20 72 6f 6f 74 6b 69 74 } //1 agony rootkit
		$a_01_1 = {25 73 20 2d 70 20 70 72 6f 63 65 73 73 2e 65 78 65 20 20 20 20 20 3a 20 68 69 64 65 20 74 68 65 20 70 72 6f 63 65 73 73 } //1 %s -p process.exe     : hide the process
		$a_03_2 = {89 44 24 10 c7 44 24 0c 16 00 00 00 c7 44 24 08 ?? ?? ?? ?? c7 44 24 04 dc ff 22 00 8b 45 ec 89 04 24 e8 ?? ?? ?? ?? 83 ec 20 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}