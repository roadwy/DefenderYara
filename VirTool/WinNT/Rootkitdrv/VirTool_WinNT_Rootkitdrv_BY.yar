
rule VirTool_WinNT_Rootkitdrv_BY{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.BY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {5c 69 33 38 36 5c 6c 61 6e 6d 61 6e 64 72 76 2e 70 64 62 } //1 \i386\lanmandrv.pdb
		$a_00_1 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 4c 00 61 00 6e 00 4d 00 61 00 6e 00 44 00 72 00 76 00 } //1 \DosDevices\LanManDrv
		$a_00_2 = {4b 00 65 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 6f 00 72 00 54 00 61 00 62 00 6c 00 65 00 } //1 KeServiceDescriptorTable
		$a_00_3 = {4d 6d 47 65 74 53 79 73 74 65 6d 52 6f 75 74 69 6e 65 41 64 64 72 65 73 73 } //1 MmGetSystemRoutineAddress
		$a_02_4 = {68 30 63 70 70 ff 75 90 01 01 6a 00 ff 15 90 00 } //1
		$a_00_5 = {fa 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 83 7d 08 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}