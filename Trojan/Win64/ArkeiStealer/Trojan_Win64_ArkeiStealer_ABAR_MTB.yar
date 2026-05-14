
rule Trojan_Win64_ArkeiStealer_ABAR_MTB{
	meta:
		description = "Trojan:Win64/ArkeiStealer.ABAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 01 f8 44 89 04 24 45 31 c2 44 8b 44 24 ?? 41 c1 c2 07 41 01 fb 45 31 dd 41 c1 c5 ?? 45 01 e8 44 31 c7 c1 c7 0c 41 01 fb 45 31 dd 41 c1 c5 ?? 45 01 e8 44 31 c7 c1 c7 07 ff 4c 24 } //5
		$a_03_1 = {89 d1 83 e1 1f 0f b6 4c 0d 00 30 0c 16 8d 4a 01 83 e1 1f 0f b6 4c 0d 00 30 4c 16 ?? 48 83 c2 02 49 39 d4 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}