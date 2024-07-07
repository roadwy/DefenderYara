
rule TrojanDropper_O97M_Obfuse_PRDF_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.PRDF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 28 72 6c 6a 74 65 6f 67 6a 78 6f 6a 64 68 71 72 65 70 6d 68 69 76 73 79 6f 72 76 6c 7a 6b 2c 20 62 79 71 73 73 78 73 7a 69 6f 6d 6c 7a 6d 6d 66 71 76 74 6f 62 75 7a 67 61 64 70 65 66 65 78 72 6e 6c 7a 29 } //1 .Run(rljteogjxojdhqrepmhivsyorvlzk, byqssxsziomlzmmfqvtobuzgadpefexrnlz)
		$a_01_1 = {3d 20 43 68 72 28 62 6e 68 66 67 20 2d 20 31 32 34 29 } //1 = Chr(bnhfg - 124)
		$a_01_2 = {3d 20 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 } //1 = "WSCript.shell"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}