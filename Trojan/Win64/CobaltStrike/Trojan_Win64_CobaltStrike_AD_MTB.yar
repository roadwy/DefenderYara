
rule Trojan_Win64_Cobaltstrike_AD_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 17 00 00 00 c1 e2 05 8b c2 41 83 e8 2c 4c 0f af c0 49 8b c2 49 f7 e0 48 c1 ea 07 48 69 c2 ff 00 00 00 41 8b d4 4c 2b c0 41 0f b6 c0 0f 45 c8 41 88 0c 39 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Cobaltstrike_AD_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 31 04 09 49 83 c1 ?? 8b 83 ?? ?? ?? ?? 01 43 ?? 8b 93 ?? ?? ?? ?? 8b 43 ?? 81 c2 ?? ?? ?? ?? 03 53 ?? 2b 43 ?? 33 d0 81 f2 ?? ?? ?? ?? 89 53 ?? 49 81 f9 ?? ?? ?? ?? 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}