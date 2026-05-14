
rule Trojan_Win64_ShellcodeLoader_AHC_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeLoader.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 89 eb 83 e3 ?? c1 eb ?? 44 89 ed 83 e5 ?? c1 ed ?? 45 89 ee 41 83 e6 ?? 41 c1 ee ?? 45 89 ec 41 } //30
		$a_03_1 = {f3 43 0f 6f 04 02 f3 42 ?? ?? ?? ?? ?? ?? ?? ?? 66 0f ef c8 48 83 c0 ?? f3 43 0f 7f 0c 01 49 83 c0 ?? 48 39 c1 75 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}