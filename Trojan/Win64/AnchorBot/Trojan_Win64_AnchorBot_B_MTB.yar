
rule Trojan_Win64_AnchorBot_B_MTB{
	meta:
		description = "Trojan:Win64/AnchorBot.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {04 02 83 f0 ?? 88 45 ?? 8b 45 ?? 04 03 83 f0 ?? 88 45 ?? 8b 45 ?? 04 04 83 f0 ?? 88 45 ?? 8b 45 ?? 04 05 33 c6 88 45 ?? 8b 45 ?? 04 06 83 f0 ?? 88 45 ?? 8b 45 ?? 04 07 83 f0 ?? 88 45 ?? 8b 45 ?? 04 08 83 f0 ?? 88 45 ?? 8b 45 ?? 04 09 83 f0 ?? 88 45 } //1
		$a_03_1 = {0f be 4c 15 ?? 83 e9 ?? 88 4c 15 ?? 49 03 d7 48 83 fa ?? 72 eb } //1
		$a_03_2 = {0f be c8 8b c2 33 c1 42 88 44 0d ?? 4d 03 cf 49 83 f9 ?? 72 e2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}