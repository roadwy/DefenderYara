
rule VirTool_WinNT_Rootkitdrv_gen_FO{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FO,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c7 45 c4 00 00 00 00 c7 45 c8 00 00 00 00 c7 45 fc 00 00 00 00 6a 04 6a 04 8b 4d d0 51 ff 15 8c 08 01 00 6a 04 6a 04 8b 55 dc 52 ff 15 90 01 04 c7 45 fc ff ff ff ff eb 22 90 00 } //01 00 
		$a_00_1 = {41 78 63 58 42 65 67 69 68 73 74 6e 61 76 76 76 73 78 78 78 78 73 46 75 63 6b 78 78 78 } //01 00  AxcXBegihstnavvvsxxxxsFuckxxx
		$a_00_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 58 00 75 00 65 00 4c 00 75 00 6f 00 } //00 00  \Device\XueLuo
	condition:
		any of ($a_*)
 
}