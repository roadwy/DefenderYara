
rule VirTool_Win64_Injeshimesz_A_MTB{
	meta:
		description = "VirTool:Win64/Injeshimesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {40 0f b6 d6 48 8b cb ?? ?? ?? ?? ?? 48 8b cb ?? ?? ?? ?? ?? 0f 57 c0 0f 11 45 d8 0f 11 45 e8 0f 11 45 f8 c7 45 d8 30 00 00 00 4c 89 74 24 58 c6 44 24 20 00 45 33 c9 ?? ?? ?? ?? ba 03 00 1f 00 } //1
		$a_03_1 = {48 8b cb 48 83 3d 9f a1 04 00 07 48 0f 47 0d 7f a1 04 00 ?? ?? ?? ?? ?? 48 89 44 24 38 44 89 74 24 30 44 89 74 24 28 44 89 74 24 20 ba 03 00 00 00 [0-14] 48 8b f8 48 83 f8 ff } //1
		$a_03_2 = {84 c0 0f 84 [0-23] 48 8b c8 [0-36] 48 83 3d 25 79 04 00 07 48 0f 47 15 05 79 04 00 4c 8b 05 0e 79 04 00 48 8b c8 } //1
		$a_03_3 = {48 8b d8 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 85 db [0-46] 48 8b c8 ?? ?? ?? ?? ?? 4c 89 74 24 28 44 89 74 24 20 45 33 c9 ?? ?? ?? ?? ?? ?? ?? 33 d2 33 c9 ?? ?? ?? ?? ?? ?? 48 8b f8 48 8b ce } //1
		$a_03_4 = {48 89 44 24 40 ?? ?? ?? ?? 48 89 44 24 38 4c 89 74 24 30 4c 89 74 24 28 44 89 74 24 20 45 33 c0 ?? ?? ?? ?? 48 8b 4c 24 68 [0-13] 85 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}