
rule VirTool_WinNT_Almanahe_D{
	meta:
		description = "VirTool:WinNT/Almanahe.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 f9 47 75 2d 80 78 01 45 75 27 80 78 02 54 75 21 80 78 03 20 75 1b 83 65 fc 00 } //1
		$a_01_1 = {68 41 57 50 31 83 c7 0c 57 6a 01 ff 15 } //1
		$a_01_2 = {45 3a 5c 44 4c 4d 6f 6e 35 5c 61 72 70 38 30 32 33 5c 6f 62 6a 5c 69 33 38 36 5c 65 74 68 38 30 32 33 2e 70 64 62 } //1 E:\DLMon5\arp8023\obj\i386\eth8023.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}