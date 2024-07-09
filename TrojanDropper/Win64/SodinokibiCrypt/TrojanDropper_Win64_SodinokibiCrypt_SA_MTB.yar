
rule TrojanDropper_Win64_SodinokibiCrypt_SA_MTB{
	meta:
		description = "TrojanDropper:Win64/SodinokibiCrypt.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 57 48 81 ec e0 00 00 00 48 8d ?? ?? ?? 48 8b f8 33 c0 b9 68 00 00 00 f3 aa c7 44 24 70 68 00 00 00 48 8d ?? ?? ?? 48 8b f8 33 c0 b9 18 00 00 00 f3 aa 48 8d 44 24 ?? 48 89 44 24 ?? 48 8d 44 24 ?? 48 89 44 24 ?? 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 45 33 c9 45 33 c0 33 d2 48 8d 0d a0 24 00 00 ff 15 ?? ?? ?? ?? 48 81 c4 e0 00 00 00 5f c3 } //1
		$a_03_1 = {8b 44 24 24 ff c0 89 44 24 ?? 8b 44 24 ?? 39 44 24 ?? 73 ?? 48 63 44 24 ?? 48 8b 4c 24 ?? 0f b6 04 01 88 44 24 ?? 0f b6 44 24 ?? 44 8b c0 48 8d 15 ?? ?? ?? ?? 48 8b 4c 24 ?? ff 15 ?? ?? ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}