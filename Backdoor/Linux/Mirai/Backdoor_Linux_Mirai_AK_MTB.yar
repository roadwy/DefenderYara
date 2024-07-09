
rule Backdoor_Linux_Mirai_AK_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 dd 4d e2 0c d0 4d e2 a0 01 9f e5 01 40 a0 e1 ?? ff ff eb 12 bd 8d e2 0f b0 8b e2 00 10 a0 e1 0b 00 a0 e1 ?? 0b 00 eb 04 30 94 e5 00 00 53 e3 7c 11 9f e5 0b 00 a0 e1 03 10 a0 11 ?? 0b 00 eb ?? 16 00 eb 00 00 50 e3 04 00 00 da 00 00 a0 e3 cc d0 8d e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}