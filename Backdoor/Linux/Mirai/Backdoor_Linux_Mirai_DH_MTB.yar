
rule Backdoor_Linux_Mirai_DH_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DH!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 00 1c 3c 90 01 02 9c 27 21 e0 99 03 e0 ff bd 27 1c 00 bf af 18 00 b0 af 10 00 bc af 52 10 02 24 0c 00 00 00 90 01 02 99 8f 06 00 e0 10 21 80 40 00 09 f8 20 03 00 00 00 00 10 00 bc 8f 00 00 50 ac ff ff 02 24 1c 00 bf 8f 18 00 b0 8f 08 00 e0 03 20 00 bd 27 90 00 } //01 00 
		$a_00_1 = {08 00 40 10 18 00 a2 27 10 82 99 8f c0 20 04 00 21 20 44 00 21 28 00 02 09 f8 20 03 08 00 06 24 10 00 bc 8f 08 00 10 26 00 00 04 8e 00 00 00 00 f3 ff 80 14 } //01 00 
		$a_01_2 = {52 4f 43 52 59 53 59 52 43 } //00 00  ROCRYSYRC
	condition:
		any of ($a_*)
 
}