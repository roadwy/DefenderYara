
rule Trojan_Win64_SpyLoader_AB_MTB{
	meta:
		description = "Trojan:Win64/SpyLoader.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 41 03 d0 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 0f be c2 6b c8 ?? 41 0f b6 c0 41 ff c0 2a c1 04 ?? 41 30 41 ?? 41 83 f8 ?? 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}