
rule Trojan_Win64_CobaltStrike_CK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b d0 48 8d 49 ?? 83 e2 ?? 49 ff c0 0f b6 04 3a 32 44 0b ?? 88 41 ?? 49 83 e9 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_CK_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 c1 41 88 4d 0f 88 83 ?? ?? 00 00 49 83 c5 10 4d 39 f5 74 } //2
		$a_01_1 = {0f b6 4c 04 1f 41 30 4c 07 ff 0f b6 4c 04 20 41 30 0c 07 48 83 c0 10 48 3d 8f 00 00 00 0f 85 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}