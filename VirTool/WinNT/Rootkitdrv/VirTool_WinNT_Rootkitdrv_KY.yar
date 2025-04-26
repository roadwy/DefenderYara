
rule VirTool_WinNT_Rootkitdrv_KY{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 45 ff 00 8b 45 24 83 20 00 8b 45 24 83 60 04 00 8b 45 20 89 45 ?? 8b 45 ?? 89 45 ?? 81 6d ?? 04 00 61 25 } //1
		$a_03_1 = {3b 45 1c 75 09 c7 45 ?? 06 00 00 80 eb 06 8b 45 ?? 83 20 00 8d 45 ?? 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}