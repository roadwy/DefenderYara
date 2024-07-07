
rule TrojanDropper_O97M_Obfuse_BHK_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.BHK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 20 50 66 52 49 4e 51 63 72 2e 4a 63 67 57 56 44 4e 6a 70 } //1 Call PfRINQcr.JcgWVDNjp
		$a_00_1 = {3d 20 52 65 70 6c 61 63 65 28 6b 45 5a 6c 6b 65 42 2c 20 22 6d 78 67 69 6d 6c 79 22 2c 20 22 22 29 } //1 = Replace(kEZlkeB, "mxgimly", "")
		$a_00_2 = {2e 52 75 6e 20 47 72 61 76 69 74 79 20 26 20 22 22 20 26 20 6b 45 5a 6c 6b 65 42 2c 20 30 2e 30 30 30 31 } //1 .Run Gravity & "" & kEZlkeB, 0.0001
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule TrojanDropper_O97M_Obfuse_BHK_MTB_2{
	meta:
		description = "TrojanDropper:O97M/Obfuse.BHK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 20 6b 46 66 70 41 71 48 41 2e 62 48 6e 51 67 78 6b } //1 Call kFfpAqHA.bHnQgxk
		$a_00_1 = {3d 20 52 65 70 6c 61 63 65 28 49 63 62 62 45 7a 74 59 62 2c 20 22 69 75 67 64 79 62 66 73 75 22 2c 20 22 22 29 } //1 = Replace(IcbbEztYb, "iugdybfsu", "")
		$a_00_2 = {2e 52 75 6e 20 47 72 61 76 69 74 79 20 26 20 22 22 20 26 20 49 63 62 62 45 7a 74 59 62 2c 20 30 2e 30 30 30 31 } //1 .Run Gravity & "" & IcbbEztYb, 0.0001
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}