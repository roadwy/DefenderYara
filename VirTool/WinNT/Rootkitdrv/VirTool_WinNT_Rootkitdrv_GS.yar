
rule VirTool_WinNT_Rootkitdrv_GS{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GS,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 0c 8b 45 08 ff 70 04 ff 15 ?? ?? ?? ?? eb 04 } //1
		$a_03_1 = {6a 04 53 ff 15 ?? ?? ?? ?? 6a 04 6a 04 56 ff 15 ?? ?? ?? ?? 83 4d fc ff 8b 1b } //1
		$a_02_2 = {53 00 70 00 79 00 77 00 61 00 72 00 65 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 90 09 20 00 [0-08] 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 } //5
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_02_2  & 1)*5) >=6
 
}