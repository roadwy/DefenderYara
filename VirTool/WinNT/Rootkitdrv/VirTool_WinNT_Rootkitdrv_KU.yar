
rule VirTool_WinNT_Rootkitdrv_KU{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {2d 1b c0 20 04 [0-08] 74 ?? 83 e8 04 74 } //1
		$a_01_1 = {c7 06 55 8b ec 51 c6 46 04 8b } //1
		$a_03_2 = {81 39 8b ff 55 8b 75 ?? 81 79 04 ec 56 64 a1 75 ?? 81 79 08 24 01 00 00 75 ?? 81 79 0c 8b 75 08 3b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}