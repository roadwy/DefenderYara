
rule Trojan_Win64_Lazy_GNS_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 30 03 49 89 dc 00 5b ?? 01 64 24 ?? 41 5c 0c ?? 85 38 } //5
		$a_01_1 = {44 67 31 20 51 10 10 86 0e } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}