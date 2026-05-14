
rule TrojanDropper_Win64_Tedy_ARA_MTB{
	meta:
		description = "TrojanDropper:Win64/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 8b c2 83 e0 1f 0f b6 44 ?? ?? ?? 32 04 ?? 88 01 48 ff c2 48 3b d3 72 e3 } //2
		$a_01_1 = {48 8b c1 83 e0 1f 0f b6 44 04 60 32 04 0e 88 04 0f 48 ff c1 48 3b cb 72 e7 } //2
		$a_01_2 = {6e 76 64 5f 25 30 38 58 2e 64 6c 6c } //3 nvd_%08X.dll
		$a_01_3 = {4e 56 44 69 73 70 6c 61 79 43 6f 6e 74 61 69 6e 65 72 2e 64 6c 6c } //3 NVDisplayContainer.dll
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=5
 
}