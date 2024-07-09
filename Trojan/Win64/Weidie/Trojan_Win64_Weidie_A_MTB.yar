
rule Trojan_Win64_Weidie_A_MTB{
	meta:
		description = "Trojan:Win64/Weidie.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 0f b6 11 44 8b 1d ?? ?? ?? ?? 41 81 e3 ?? ?? ?? ?? 45 33 d3 45 8b d2 47 33 04 91 44 89 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}