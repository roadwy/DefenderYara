
rule Backdoor_Linux_Mirai_GH_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GH!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 82 99 8f 00 00 a0 a0 09 f8 20 03 21 20 c0 02 18 00 bc 8f 21 20 c0 02 58 82 99 8f 2c 00 a0 af 30 00 a0 af 34 00 a0 af 38 00 a0 af 09 f8 20 03 21 88 c2 02 18 00 bc 8f 11 00 42 24 } //01 00 
		$a_03_1 = {58 82 99 8f d4 10 a4 8f 09 f8 20 03 00 00 00 00 d4 10 a4 8f bc 08 a3 97 21 10 82 00 05 00 46 24 c0 10 a2 8f 18 00 bc 8f d5 ff 90 01 03 b0 80 00 c2 08 a3 97 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}