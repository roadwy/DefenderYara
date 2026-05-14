
rule Trojan_Win64_CobaltStrike_GKI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 d8 4c 39 d0 73 ?? 45 8d 44 18 ?? 41 31 d8 66 44 33 04 41 66 45 89 04 41 48 83 e2 ?? 31 c0 66 41 89 04 11 } //1
		$a_03_1 = {44 0f b7 04 41 45 31 d8 41 83 c3 ?? 41 31 c0 66 45 89 04 41 48 83 c0 ?? 49 39 c2 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}