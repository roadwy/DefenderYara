
rule VirTool_WinNT_Rootkitdrv_HG{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.HG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_08_0 = {3f 3f 5c 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c } //01 00  ??\C:\WINDOWS\system32\
		$a_08_1 = {2e 65 78 65 00 } //01 00 
		$a_03_2 = {89 48 40 c7 40 34 90 01 04 33 c9 33 c0 f6 90 90 90 01 04 40 3d 00 01 00 00 7c f2 90 00 } //01 00 
		$a_03_3 = {7e 40 c7 45 fc 90 01 04 8d 34 bd 90 01 04 83 3e 00 75 21 ff 75 fc e8 90 01 04 85 c0 75 06 c7 06 01 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}