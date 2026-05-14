
rule Trojan_Win64_XLoader_AHC_MTB{
	meta:
		description = "Trojan:Win64/XLoader.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 45 2b 50 10 41 8b c2 41 89 40 ?? 8b c7 99 41 f7 fa 8d b8 ?? ?? ?? ?? e9 } //30
		$a_03_1 = {8b c2 41 f7 ee 44 8b f2 41 c1 ee ?? c1 fa ?? 44 03 f2 44 33 f1 e9 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}