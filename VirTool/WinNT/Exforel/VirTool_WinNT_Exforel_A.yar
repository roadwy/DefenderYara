
rule VirTool_WinNT_Exforel_A{
	meta:
		description = "VirTool:WinNT/Exforel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {78 31 34 31 20 63 6d 64 20 73 68 65 6c 6c 0d 0a } //1
		$a_01_1 = {5c 5c 2e 5c 50 69 70 65 5c 78 31 34 31 5f 73 74 64 6f 75 74 } //1 \\.\Pipe\x141_stdout
		$a_01_2 = {68 70 61 6d 78 } //1 hpamx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}