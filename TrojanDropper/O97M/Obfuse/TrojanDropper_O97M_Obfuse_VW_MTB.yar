
rule TrojanDropper_O97M_Obfuse_VW_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.VW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 61 6b 65 53 75 72 65 44 69 72 65 63 74 6f 72 79 50 61 74 68 45 78 69 73 74 73 } //1 MakeSureDirectoryPathExists
		$a_00_1 = {3d 20 22 63 3a 5c 49 6e 73 74 61 6c 6c 53 68 69 65 6c 64 5c 22 } //1 = "c:\InstallShield\"
		$a_03_2 = {3d 20 73 74 72 50 61 72 68 20 26 20 22 [0-0a] 22 20 26 20 22 2e 62 61 74 22 } //1
		$a_00_3 = {3d 20 22 63 3a 5c 44 61 74 61 69 6e 76 5c 22 } //1 = "c:\Datainv\"
		$a_03_4 = {3d 20 72 65 63 6f 72 64 20 26 20 22 [0-0a] 22 20 26 20 22 2e 62 61 74 22 } //1
		$a_03_5 = {53 74 61 72 74 50 72 6f 63 65 73 73 20 [0-0a] 2c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}