
rule Trojan_Win64_Sidlodll_DA_MTB{
	meta:
		description = "Trojan:Win64/Sidlodll.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 48 8b c3 48 f7 e1 48 c1 ea 04 48 8d 04 d2 48 03 c0 48 2b c8 49 0f af cf 0f b6 44 0d ?? 43 32 44 31 fc 41 88 41 ff } //1
		$a_03_1 = {48 63 c8 48 8b c3 48 f7 e1 48 c1 ea 04 48 6b c2 13 48 2b c8 49 0f af cf 0f b6 44 0d ?? 43 32 44 31 fc 41 88 41 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}