
rule Trojan_Win64_CobaltStrike_ZK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 4c 8b 04 25 60 00 00 00 4d 8b 40 18 4d 8b 40 20 4d 89 c3 49 8b 50 50 51 4c 89 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_ZK_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 b8 ?? ?? ?? ?? 2a c2 0f be c0 6b c8 ?? 41 02 c8 41 ff c0 41 30 09 49 ff c1 41 83 f8 16 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}