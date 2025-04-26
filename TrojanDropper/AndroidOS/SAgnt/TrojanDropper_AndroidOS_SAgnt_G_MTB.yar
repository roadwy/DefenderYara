
rule TrojanDropper_AndroidOS_SAgnt_G_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.G!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 40 8d ab ?? 03 00 00 0f b6 4c 11 01 32 4c 05 00 83 c0 01 39 44 24 1c 88 0c 17 b9 00 00 00 00 0f 44 c1 83 c2 01 39 d6 75 d4 } //1
		$a_03_1 = {0f b6 84 1d 00 ?? ?? ?? 8d 8b ?? 03 00 00 89 74 24 04 32 04 39 83 c7 01 0f be c0 89 04 24 e8 ?? f6 ff ff 3b 7c 24 28 b8 00 00 00 00 0f 44 f8 83 c5 01 81 fd ?? ?? 01 00 75 c6 89 34 24 e8 ?? f6 ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}