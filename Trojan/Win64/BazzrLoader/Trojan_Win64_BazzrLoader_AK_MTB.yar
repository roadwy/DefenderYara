
rule Trojan_Win64_BazzrLoader_AK_MTB{
	meta:
		description = "Trojan:Win64/BazzrLoader.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 33 c9 45 69 c0 ?? ?? ?? ?? b8 ?? ?? ?? ?? 41 81 c0 ?? ?? ?? ?? 41 8b c8 c1 e9 10 f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 0e 69 c0 ff 7f 00 00 2b c8 42 89 4c 8c ?? 49 ff c1 49 83 f9 0e 7c } //1
		$a_03_1 = {80 74 04 48 ?? 48 ff c0 48 83 f8 0f 7c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}