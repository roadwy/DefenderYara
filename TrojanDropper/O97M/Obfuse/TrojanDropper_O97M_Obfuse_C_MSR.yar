
rule TrojanDropper_O97M_Obfuse_C_MSR{
	meta:
		description = "TrojanDropper:O97M/Obfuse.C!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 63 68 69 63 6b 65 6e 70 72 69 63 65 22 } //1 Attribute VB_Name = "chickenprice"
		$a_02_1 = {3d 20 42 65 6e 61 6a 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c [0-02] 5c 6b 65 79 6c 6f 61 64 [0-10] 2e 63 6d 64 22 2c 20 54 72 75 65 29 } //1
		$a_00_2 = {73 74 61 72 74 20 43 3a 5c 31 5c 57 6f 6d 61 6e 4c 6f 76 65 2e 65 78 65 } //1 start C:\1\WomanLove.exe
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}