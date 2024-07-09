
rule Trojan_Win64_IcedID_MW_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 ec 41 03 d4 c1 fa 04 8b c2 c1 e8 1f 03 d0 41 8b c4 41 ff c4 6b d2 1d 2b c2 48 63 c8 48 8b 44 24 28 42 8a 8c 31 ?? ?? ?? ?? 41 32 0c 00 43 88 0c 18 49 ff c0 44 3b 64 24 20 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win64_IcedID_MW_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 4f 62 6a 65 63 74 } //10 RunObject
		$a_01_1 = {71 33 6d 67 75 47 35 56 2e 64 6c 6c } //1 q3mguG5V.dll
		$a_01_2 = {44 47 6c 44 39 46 37 74 68 45 } //1 DGlD9F7thE
		$a_01_3 = {49 72 50 55 71 4e 35 73 36 46 56 } //1 IrPUqN5s6FV
		$a_01_4 = {65 51 6a 4b 75 6a 68 } //1 eQjKujh
		$a_01_5 = {6c 4e 67 74 6e 4a } //1 lNgtnJ
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win64_IcedID_MW_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //10 PluginInit
		$a_01_1 = {54 41 62 5a 39 36 2e 64 6c 6c } //1 TAbZ96.dll
		$a_01_2 = {41 6e 56 6e 73 74 36 } //1 AnVnst6
		$a_01_3 = {46 65 5a 31 71 48 51 38 54 37 } //1 FeZ1qHQ8T7
		$a_01_4 = {67 33 68 78 62 6c 41 4e 63 37 4b } //1 g3hxblANc7K
		$a_01_5 = {7a 4e 4d 35 6c 57 73 37 4c 51 } //1 zNM5lWs7LQ
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win64_IcedID_MW_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 40 48 89 44 24 10 eb ?? 48 89 44 24 40 48 83 7c 24 10 00 76 ?? eb ?? 48 8b 44 24 30 48 83 c4 28 eb ?? 4c 89 44 24 18 48 89 54 24 10 eb ?? 8a 09 88 08 eb } //10
		$a_01_1 = {4a 6e 61 73 64 68 62 6a 61 73 64 73 } //5 Jnasdhbjasds
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}