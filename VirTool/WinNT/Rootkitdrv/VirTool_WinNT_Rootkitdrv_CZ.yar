
rule VirTool_WinNT_Rootkitdrv_CZ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.CZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {81 38 8b ff 55 8b 75 ?? 81 78 04 ec 5d ff 25 75 ?? 8b 48 08 89 4d ?? 8b 09 } //1
		$a_00_1 = {43 4c 41 53 53 50 4e 50 2e 53 59 53 } //1 CLASSPNP.SYS
		$a_00_2 = {5c 44 65 76 69 63 65 5c 48 61 72 64 64 69 73 6b 30 5c 44 52 30 } //1 \Device\Harddisk0\DR0
		$a_00_3 = {4d 6d 47 65 74 53 79 73 74 65 6d 52 6f 75 74 69 6e 65 41 64 64 72 65 73 73 } //1 MmGetSystemRoutineAddress
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}