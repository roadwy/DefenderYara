
rule Trojan_Win64_ZLoader_YAC_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 2b c8 49 0f af ca 0f b6 44 0c ?? 42 32 44 03 fa 41 88 40 fa } //11
	condition:
		((#a_03_0  & 1)*11) >=11
 
}