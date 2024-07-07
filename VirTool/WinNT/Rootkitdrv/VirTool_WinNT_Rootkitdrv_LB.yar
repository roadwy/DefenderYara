
rule VirTool_WinNT_Rootkitdrv_LB{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c2 08 00 8b 45 0c 0f b7 04 43 8b 04 87 eb ed } //1
		$a_01_1 = {8b 7e 1c 8b 46 20 8b 5e 24 83 65 0c 00 03 f9 03 c1 03 d9 83 7e 18 00 76 } //1
		$a_00_2 = {8b ca 83 e1 03 f3 a4 81 78 20 32 54 76 98 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}