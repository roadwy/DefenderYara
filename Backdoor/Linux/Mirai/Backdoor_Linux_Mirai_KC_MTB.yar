
rule Backdoor_Linux_Mirai_KC_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 85 8c 74 01 b9 8f 21 20 40 02 09 f8 20 03 24 00 a6 27 21 88 40 00 ff ff 02 24 18 00 bc 8f cd ?? ?? ?? 21 10 51 02 21 80 40 02 0b 00 13 24 } //1
		$a_03_1 = {64 01 b9 8f 21 28 80 00 09 f8 20 03 24 00 a7 27 21 88 40 00 ff ff 02 24 18 00 bc 8f 6b 00 22 16 21 80 00 00 d8 ?? ?? ?? ff ff 17 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}