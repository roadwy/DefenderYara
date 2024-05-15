
rule Backdoor_Linux_Mirai_FK_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {60 30 9f e5 00 00 53 e3 03 90 01 03 0f e0 a0 e1 03 f0 a0 e1 00 30 a0 e3 00 30 80 e5 18 30 9f e5 06 10 a0 e1 00 20 93 e5 08 00 a0 e1 0f e0 a0 e1 0a f0 a0 e1 83 fe ff eb 90 00 } //01 00 
		$a_02_1 = {0f 00 00 0a 01 c0 53 e2 0d 90 01 03 02 0b 1e e3 0b 90 01 03 01 00 5c e3 21 90 01 03 28 30 90 01 01 e5 00 00 53 e3 1e 90 01 03 03 30 d0 e5 2c 20 90 01 01 e5 0c 30 63 e0 00 00 52 e3 01 c0 43 e2 02 30 d0 c5 0c c0 63 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}