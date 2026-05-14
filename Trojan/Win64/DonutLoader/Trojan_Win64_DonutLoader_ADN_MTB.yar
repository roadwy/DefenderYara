
rule Trojan_Win64_DonutLoader_ADN_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.ADN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 c9 33 c9 e8 ?? ?? ?? ?? 48 8b 55 68 8b f8 48 83 fa 0f 76 36 48 8b 4d 50 48 ff c2 48 81 fa ?? ?? ?? ?? 72 1b 4c 8b 41 f8 49 2b c8 48 83 e9 08 48 83 f9 1f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_DonutLoader_ADN_MTB_2{
	meta:
		description = "Trojan:Win64/DonutLoader.ADN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 89 f0 48 f7 d8 0f 80 ?? 09 00 00 4c 8b ?? ?? 04 00 00 48 8d 0d ?? ?? 01 00 e8 ?? ?? 01 00 48 85 c0 0f 84 ?? 09 00 00 49 89 ?? 48 8d 15 ?? ?? 01 00 48 89 c1 } //2
		$a_01_1 = {73 69 6c 65 6e 74 72 69 66 74 5f 6c 6f 61 64 65 72 2e 70 64 62 } //1 silentrift_loader.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}