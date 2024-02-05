
rule Backdoor_Linux_Mirai_CD_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CD!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {f0 4f 2d e9 08 54 9f e5 08 34 9f e5 05 50 8f e0 03 40 95 e7 00 00 54 e3 83 df 4d e2 0b 00 00 1a f4 03 9f e5 19 1e 8d e2 00 00 85 e0 2c 02 00 eb 00 00 50 e3 d0 41 8d 15 e0 13 9f e5 d0 21 9d e5 01 30 95 e7 02 00 53 e1 01 20 85 17 02 01 00 1b } //00 00 
	condition:
		any of ($a_*)
 
}