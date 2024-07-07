
rule Backdoor_Linux_Mirai_HA_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {04 11 00 a5 27 fe 00 00 27 bd ff fc af bf 00 00 00 a4 28 20 ac e6 00 00 3c 0d 80 00 01 a0 48 21 24 0b 00 01 04 11 00 42 24 0f 00 01 11 c0 00 05 90 8e 00 00 24 84 00 01 24 c6 00 01 } //1
		$a_00_1 = {8c e3 00 00 00 85 c0 23 8f bf 00 00 af b8 00 00 00 60 20 21 00 c3 28 23 ac e5 00 00 24 06 00 03 24 02 10 33 00 00 00 0c 8f a2 00 00 03 e0 00 08 27 bd 00 04 24 06 00 1e 04 11 00 0c 03 e0 28 21 50 52 4f 54 5f 45 58 45 43 7c 50 52 4f 54 5f 57 52 49 54 45 20 66 61 69 6c 65 64 2e 0a 00 0a 00 0a 00 34 2e 30 30 32 30 32 31 0a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}