
rule VirTool_WinNT_Rootkitdrv_gen_GB{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!GB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 05 00 00 "
		
	strings :
		$a_02_0 = {83 7d 14 20 72 ?? 8b 45 10 85 c0 74 ?? 8b 08 89 0d ?? ?? ?? ?? 8b 48 04 89 0d ?? ?? ?? ?? 8b 48 08 } //10
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 6b 00 61 00 76 00 73 00 76 00 63 00 } //1 \Device\kavsvc
		$a_00_2 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 6b 00 61 00 76 00 73 00 76 00 63 00 } //1 \DosDevices\kavsvc
		$a_00_3 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 6b 00 61 00 76 00 6c 00 65 00 63 00 } //1 \DosDevices\kavlec
		$a_00_4 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 6b 00 61 00 76 00 6c 00 65 00 63 00 } //1 \Device\kavlec
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=10
 
}