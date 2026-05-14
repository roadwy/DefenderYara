
rule Trojan_Win64_Loader_AHB_MTB{
	meta:
		description = "Trojan:Win64/Loader.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 cb 0f be c3 80 e1 ?? 41 b9 ?? ?? ?? ?? c0 e1 ?? 41 d3 e9 44 32 4c 1c 40 6b c8 ?? 44 32 c9 49 3b d0 73 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}