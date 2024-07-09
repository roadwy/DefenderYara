
rule VirTool_WinNT_Rootkitdrv_GC{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {59 f3 ab a1 ?? ?? 01 00 83 f8 20 bf ?? ?? 01 00 76 0d 83 f8 78 77 08 } //1
		$a_03_1 = {81 f9 67 e0 22 00 0f 85 ?? ?? ?? ?? 83 65 fc 00 6a 04 6a 04 53 ff 15 ?? ?? 01 00 83 4d fc ff 8b 1b a1 ?? ?? 01 00 39 58 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}