
rule Trojan_Win64_Emotet_BK_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 01 32 4c 3e ff 49 ff cd 88 4f ff 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_BK_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 01 42 32 4c 16 fd 41 88 4a ff 49 ff ce 0f 85 48 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_BK_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {d1 e8 03 c2 8b d7 c1 e8 ?? ff c7 6b c0 ?? 2b d0 48 8b 05 ?? ?? ?? ?? 4c 63 c2 48 8b 15 ?? ?? ?? ?? 45 8a 0c 00 44 32 8c 1d ?? ?? ?? ?? 44 88 0c 13 48 ff c3 48 3b de 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}