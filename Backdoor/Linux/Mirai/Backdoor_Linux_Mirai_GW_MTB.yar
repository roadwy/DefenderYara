
rule Backdoor_Linux_Mirai_GW_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 6e ff dc 2d 68 00 08 ff e0 20 6e ff dc 21 6e ff d4 00 08 20 6e ff e0 21 6e ff d4 00 0c 70 01 80 ae ff e8 20 6e ff d4 21 40 00 04 20 6e ff d4 21 6e ff dc 00 0c 20 6e ff d4 21 6e ff e0 00 08 22 2e ff d4 20 2e ff e8 d0 81 20 40 20 ae ff e8 } //01 00 
		$a_01_1 = {70 34 d0 ae ff d0 2d 40 ff f0 20 6e ff f0 2d 68 00 08 ff f4 20 6e ff d4 21 6e ff f0 00 0c 20 6e ff d4 21 6e ff f4 00 08 20 6e ff f0 21 6e ff d4 00 08 20 6e ff f4 21 6e ff d4 00 0c 70 01 80 ae ff d8 20 6e ff d4 21 40 00 04 22 2e ff d4 20 2e ff d8 d0 81 20 40 20 ae ff d8 } //00 00 
	condition:
		any of ($a_*)
 
}