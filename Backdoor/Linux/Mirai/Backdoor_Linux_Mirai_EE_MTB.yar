
rule Backdoor_Linux_Mirai_EE_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 c6 8f e2 15 ca 8c e2 60 fa bc e5 00 c6 8f e2 15 ca 8c e2 58 fa bc e5 00 c6 8f e2 15 ca 8c e2 50 fa bc e5 00 c6 8f e2 15 ca 8c e2 48 fa bc e5 00 c6 8f e2 15 ca 8c e2 40 fa bc e5 00 c6 8f e2 15 ca 8c e2 38 fa bc e5 00 c6 8f e2 15 ca 8c e2 30 fa bc e5 00 c6 8f e2 15 ca 8c e2 28 fa bc e5 00 c6 8f e2 15 ca 8c e2 20 fa bc e5 00 c6 8f e2 15 ca 8c e2 18 fa bc e5 00 c6 8f e2 15 ca 8c e2 10 fa bc e5 00 c6 8f e2 15 ca 8c e2 08 fa bc e5 00 c6 8f e2 15 ca 8c e2 00 fa bc e5 30 40 2d e9 5c 50 9f e5 00 30 d5 e5 00 00 53 e3 30 80 bd 18 50 40 9f e5 00 30 94 e5 00 20 93 e5 00 00 52 e3 07 00 00 0a 04 30 83 e2 00 30 84 e5 0f e0 a0 e1 02 f0 a0 e1 00 30 94 e5 00 20 93 e5 00 00 52 e3 f7 ff ff 1a } //00 00 
	condition:
		any of ($a_*)
 
}