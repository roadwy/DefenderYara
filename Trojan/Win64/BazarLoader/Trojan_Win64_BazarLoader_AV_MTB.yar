
rule Trojan_Win64_BazarLoader_AV_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {45 4e 4f 6e 6d 46 2e 70 64 62 } //ENOnmF.pdb  3
		$a_80_1 = {43 6e 49 4e 65 50 63 78 79 } //CnINePcxy  3
		$a_80_2 = {44 6b 78 4b 50 67 42 79 7a 49 74 53 6a 59 4e 61 6e 4d } //DkxKPgByzItSjYNanM  3
		$a_80_3 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //IsProcessorFeaturePresent  3
		$a_80_4 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 45 78 57 } //FindFirstFileExW  3
		$a_80_5 = {47 65 74 43 6f 6e 73 6f 6c 65 4f 75 74 70 75 74 43 50 } //GetConsoleOutputCP  3
		$a_80_6 = {44 5f 4b 47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 57 20 41 4f 4d 57 4c 40 54 78 4e 48 41 4e 73 } //D_KGetModuleHandleW AOMWL@TxNHANs  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win64_BazarLoader_AV_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.AV!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 48 83 ec 20 48 63 41 3c 8b fa 4c 8b d9 8b 9c 08 88 00 00 00 8b ac 08 8c 00 00 00 48 03 d9 8b c2 c1 e8 10 66 85 c0 75 08 0f b7 c7 2b 43 10 eb 72 44 8b 43 20 45 33 c9 44 8b 53 24 4d 03 c3 8b 73 18 4d 03 d3 85 f6 74 3f } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}