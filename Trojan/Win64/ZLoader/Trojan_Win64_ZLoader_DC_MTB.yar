
rule Trojan_Win64_ZLoader_DC_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 17 48 2b c8 0f b6 44 0d ?? 43 32 04 22 49 83 c2 06 43 88 44 0a } //10
		$a_03_1 = {48 c1 ea 04 48 6b c2 11 48 2b c8 49 0f af cb 0f b6 44 0c ?? 42 32 44 0b ff 41 88 41 ff } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}