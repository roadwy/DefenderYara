
rule VirTool_WinNT_Rootkitdrv_GF{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GF,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 88 88 00 00 00 89 4d f8 8b 55 08 8b 82 8c 00 00 00 89 45 fc 8b 45 f8 8b 4d fc 89 48 04 8b 55 fc 8b 45 f8 89 02 b0 01 } //5
		$a_01_1 = {81 7d d0 00 20 37 81 74 02 } //1
		$a_00_2 = {48 65 6c 6c 6f 2c 20 54 6f 20 50 72 6f 63 65 73 73 5f 68 69 64 65 } //1 Hello, To Process_hide
		$a_00_3 = {48 65 6c 6c 6f 2c 20 66 72 6f 6d 20 44 72 69 76 65 72 45 6e 74 72 79 } //1 Hello, from DriverEntry
		$a_00_4 = {42 79 65 2c 20 66 72 6f 6d 20 44 72 69 76 65 72 55 6e 6c 6f 61 64 } //1 Bye, from DriverUnload
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}