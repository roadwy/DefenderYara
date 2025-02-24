
rule Trojan_Win64_ZLoader_YAE_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 6b c2 13 48 2b c8 49 0f af cb 0f b6 44 0c ?? 42 32 44 0b fb 41 88 41 fb 41 8d 42 } //11
		$a_03_1 = {48 03 c0 48 2b c8 49 0f af cb 0f b6 44 0c ?? 42 32 44 17 ff 41 88 42 } //11
	condition:
		((#a_03_0  & 1)*11+(#a_03_1  & 1)*11) >=11
 
}