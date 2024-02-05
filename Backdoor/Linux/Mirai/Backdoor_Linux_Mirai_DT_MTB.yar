
rule Backdoor_Linux_Mirai_DT_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {20 21 92 e3 00 00 8f bc 00 18 10 60 00 65 00 00 00 00 02 e0 10 21 8f bf 10 fc 8f be 10 f8 8f b7 10 f4 8f b6 10 f0 8f b5 10 ec 8f b4 10 e8 8f b3 10 e4 8f b2 10 e0 8f b1 10 dc 8f b0 10 d8 03 e0 00 08 27 bd 11 00 8f 99 82 } //01 00 
		$a_00_1 = {10 21 30 42 ff ff af a2 10 c0 3c 02 08 08 34 42 08 08 24 03 01 00 af a2 00 30 8f a2 10 c0 a6 23 00 02 27 a3 00 3c a6 22 00 00 24 14 ff ff a4 e6 00 02 a6 06 00 01 af a3 10 cc af a4 10 d0 24 1e 00 05 12 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}