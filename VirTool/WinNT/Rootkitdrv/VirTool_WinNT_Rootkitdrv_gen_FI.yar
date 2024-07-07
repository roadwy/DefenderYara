
rule VirTool_WinNT_Rootkitdrv_gen_FI{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FI,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 c2 03 32 10 40 80 38 00 75 f5 8b c2 5a c9 c2 04 00 } //1
		$a_01_1 = {89 95 fc fc ff ff c7 45 fc fe ff ff ff 89 95 ec fc ff ff 89 95 f0 fc ff ff 8d 8a 00 00 10 00 89 8d e8 fc ff ff c7 85 18 fd ff ff 07 00 01 00 89 9d a4 fd ff ff c7 85 a8 fd ff ff 3b 00 00 00 6a 23 58 89 85 ac fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}