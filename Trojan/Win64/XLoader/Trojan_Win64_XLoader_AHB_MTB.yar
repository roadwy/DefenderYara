
rule Trojan_Win64_XLoader_AHB_MTB{
	meta:
		description = "Trojan:Win64/XLoader.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 2b c2 41 03 c8 8b d1 89 50 ?? 8b 44 24 64 99 f7 f9 8d b0 ?? ?? ?? ?? e9 } //30
		$a_03_1 = {8b c2 f7 ef 03 fa 8b d7 c1 ea ?? c1 ff ?? 03 fa 33 f9 e9 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}