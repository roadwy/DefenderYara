
rule VirTool_WinNT_Rootkitdrv_HG{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.HG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_08_0 = {3f 3f 5c 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c } //1 ??\C:\WINDOWS\system32\
		$a_08_1 = {2e 65 78 65 00 } //1
		$a_03_2 = {89 48 40 c7 40 34 ?? ?? ?? ?? 33 c9 33 c0 f6 90 90 ?? ?? ?? ?? 40 3d 00 01 00 00 7c f2 } //1
		$a_03_3 = {7e 40 c7 45 fc ?? ?? ?? ?? 8d 34 bd ?? ?? ?? ?? 83 3e 00 75 21 ff 75 fc e8 ?? ?? ?? ?? 85 c0 75 06 c7 06 01 00 00 00 } //1
	condition:
		((#a_08_0  & 1)*1+(#a_08_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}