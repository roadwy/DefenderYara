
rule TrojanDropper_O97M_Obfuse_AK_MSR{
	meta:
		description = "TrojanDropper:O97M/Obfuse.AK!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {3d 20 55 73 65 72 46 6f 72 6d 32 2e 54 65 78 74 42 6f 78 32 2e 54 61 67 20 2b 20 22 5c 7b [0-24] 7d 32 2e 64 6c 6c 22 } //1
		$a_00_1 = {28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 ("Shell.Application")
		$a_02_2 = {6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 [0-10] 29 2e 43 6f 70 79 48 65 72 65 20 6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 [0-10] 29 2e 69 74 65 6d 73 2e 49 74 65 6d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}