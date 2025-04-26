
rule Trojan_O97M_Donoff_BC_MTB{
	meta:
		description = "Trojan:O97M/Donoff.BC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {22 4d 69 63 72 6f 73 6f 66 74 2e 57 22 0d 0a 20 20 20 20 [0-05] 20 3d 20 90 1b 00 20 26 20 22 69 6e 64 6f 77 73 2e 41 22 } //1
		$a_01_1 = {3d 20 62 36 34 44 65 63 6f 64 65 28 73 74 61 67 65 5f 31 29 } //1 = b64Decode(stage_1)
		$a_01_2 = {53 65 74 20 61 63 74 43 74 78 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //1 Set actCtx = CreateObject(
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}