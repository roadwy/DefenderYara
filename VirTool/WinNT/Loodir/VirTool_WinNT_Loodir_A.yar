
rule VirTool_WinNT_Loodir_A{
	meta:
		description = "VirTool:WinNT/Loodir.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 13 00 00 00 bf ?? ?? ?? ?? f3 a5 0f b7 0d ?? ?? ?? ?? 81 f9 55 aa 00 00 74 11 b9 80 00 00 00 be 28 52 01 00 } //1
		$a_01_1 = {81 b8 40 60 00 00 65 56 43 34 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}