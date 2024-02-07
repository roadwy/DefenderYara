
rule TrojanDropper_O97M_Obfuse_RSM_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.RSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 41 4d 62 59 4f 37 44 4c 20 2b 20 53 43 49 32 76 4f 39 77 20 2b 20 56 65 38 78 54 77 75 4d 20 2b 20 70 77 42 6d 47 68 72 79 20 2b 20 4b 41 66 48 75 79 6a 41 29 } //01 00  CreateObject(AMbYO7DL + SCI2vO9w + Ve8xTwuM + pwBmGhry + KAfHuyjA)
		$a_01_1 = {42 6e 6d 5a 6a 41 43 67 2e 52 75 6e } //01 00  BnmZjACg.Run
		$a_01_2 = {4c 34 68 56 4d 46 20 28 31 38 29 } //01 00  L4hVMF (18)
		$a_01_3 = {57 68 69 6c 65 20 54 69 6d 65 72 20 2d 20 74 65 6d 70 20 3c 20 73 65 63 } //00 00  While Timer - temp < sec
	condition:
		any of ($a_*)
 
}