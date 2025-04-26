
rule Trojan_Win64_Cobaltstrike_HL_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.HL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 c9 07 c1 7d 00 81 f1 97 57 23 b8 41 30 0c 06 69 c9 07 c1 7d 00 81 f1 97 57 23 b8 41 30 4c 06 01 48 83 c0 02 48 39 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Cobaltstrike_HL_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.HL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 08 8b c3 99 41 f7 fa 48 63 c2 42 0f b6 14 38 2b ca 81 c1 ?? ?? ?? ?? 81 e1 ?? ?? ?? ?? 7d ?? ff c9 81 c9 ?? ?? ?? ?? ff c1 41 88 08 ff c3 49 ff c0 49 83 e9 01 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}