
rule VirTool_WinNT_Rootkitdrv_CO{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.CO,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //2 KeServiceDescriptorTable
		$a_00_1 = {4d 00 73 00 4d 00 67 00 72 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 20 00 66 00 6f 00 72 00 20 00 50 00 72 00 6f 00 63 00 74 00 65 00 63 00 74 00 } //2 MsMgr Driver for Proctect
		$a_01_2 = {68 53 59 53 48 ff 70 08 6a 00 } //1
		$a_01_3 = {68 48 41 53 48 68 34 04 00 00 6a 00 ff 15 } //1
		$a_01_4 = {74 21 8a 11 80 fa 2a 74 1a 3c 61 7c 06 } //1
		$a_01_5 = {68 48 4f 4f 4b 50 6a 00 89 45 08 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}