
rule VirTool_WinNT_Rootkitdrv_LW{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 } //1 \SystemRoot\system32\drivers\etc\hosts
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 52 00 65 00 67 00 47 00 75 00 61 00 72 00 64 00 } //1 \Device\RegGuard
		$a_03_2 = {83 7d 14 01 75 13 ff 75 1c ff 75 18 e8 90 01 04 84 c0 74 04 33 c0 eb 18 ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 90 01 02 01 00 c9 c2 18 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}