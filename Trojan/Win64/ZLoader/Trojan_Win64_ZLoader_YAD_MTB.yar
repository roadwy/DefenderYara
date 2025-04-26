
rule Trojan_Win64_ZLoader_YAD_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b c4 48 f7 e1 48 c1 ea 04 48 ?? ?? ?? 48 03 c0 48 2b c8 0f b6 44 0c ?? 43 32 44 0f ?? 41 88 41 } //11
	condition:
		((#a_03_0  & 1)*11) >=11
 
}