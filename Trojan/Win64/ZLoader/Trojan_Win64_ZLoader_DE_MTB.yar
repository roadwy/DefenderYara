
rule Trojan_Win64_ZLoader_DE_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c3 48 f7 e1 48 c1 ea 02 48 6b c2 16 48 2b c8 0f b6 44 0d ?? 43 32 44 22 ?? 43 88 44 0a fe } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}