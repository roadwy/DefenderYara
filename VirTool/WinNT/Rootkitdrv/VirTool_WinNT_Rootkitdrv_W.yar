
rule VirTool_WinNT_Rootkitdrv_W{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.W,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 07 00 00 "
		
	strings :
		$a_02_0 = {74 25 8b 4d ?? 8b 14 8d ?? ?? ?? ?? 8b 45 ?? 8a 0c 02 80 f1 ?? 8b 55 ?? 8b 04 95 ?? ?? ?? ?? 8b 55 ?? 88 0c 10 } //10
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 64 00 70 00 74 00 69 00 } //10 \Device\dpti
		$a_00_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 49 00 50 00 46 00 49 00 4c 00 54 00 45 00 52 00 44 00 52 00 49 00 56 00 45 00 52 00 } //10 \Device\IPFILTERDRIVER
		$a_00_3 = {00 64 72 77 65 62 2e 00 } //1 搀睲扥.
		$a_00_4 = {00 61 67 6e 6d 69 74 75 6d 2e 00 } //1
		$a_00_5 = {00 73 79 6d 61 6e 74 65 63 2e 00 } //1
		$a_00_6 = {00 6b 61 73 70 65 72 73 6b 79 00 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=33
 
}