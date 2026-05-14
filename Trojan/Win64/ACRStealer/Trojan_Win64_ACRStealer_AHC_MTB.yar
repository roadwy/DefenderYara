
rule Trojan_Win64_ACRStealer_AHC_MTB{
	meta:
		description = "Trojan:Win64/ACRStealer.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 cb c1 e1 ?? 31 d9 89 cb c1 e9 ?? 31 d9 89 cb c1 e1 ?? 31 d9 90 90 89 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 85 c9 75 } //30
		$a_01_1 = {44 0f b6 24 16 45 31 d4 45 88 24 18 48 ff c3 4c 89 c0 4c 89 da 48 39 d9 7e } //20
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}