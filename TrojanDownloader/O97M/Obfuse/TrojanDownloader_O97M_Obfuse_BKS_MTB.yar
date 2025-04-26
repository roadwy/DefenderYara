
rule TrojanDownloader_O97M_Obfuse_BKS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BKS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 28 70 68 61 79 6b 68 70 6f 75 66 76 78 6f 65 6e 76 72 69 72 65 74 77 2c 20 6f 63 74 6f 69 77 77 6f 6a 67 62 65 76 6b 70 6e 77 79 68 7a 65 6b 74 73 6e 6e 79 64 79 7a 73 29 } //1 .Run(phaykhpoufvxoenvriretw, octoiwwojgbevkpnwyhzektsnnydyzs)
		$a_01_1 = {3d 20 43 68 72 28 62 6e 68 66 67 20 2d 20 31 32 34 29 } //1 = Chr(bnhfg - 124)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}