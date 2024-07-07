
rule VirTool_WinNT_Rootkitdrv_KP{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 61 00 67 00 6f 00 6e 00 79 00 } //1 \Device\agony
		$a_00_1 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 61 00 67 00 6f 00 6e 00 79 00 } //1 \DosDevices\agony
		$a_03_2 = {8b 48 01 8b 12 8b 0c 8a 89 0d 90 01 04 fa 8b 40 01 8b 15 90 01 04 b9 90 01 04 8d 04 82 87 08 89 0d 90 01 04 fb 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}