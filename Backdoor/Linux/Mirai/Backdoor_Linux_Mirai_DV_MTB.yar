
rule Backdoor_Linux_Mirai_DV_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DV!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 30 73 61 78 30 61 73 66 64 30 30 64 64 64 2e 6c 6f 73 65 79 6f 75 72 69 70 2e 63 6f 6d } //01 00  00sax0asfd00ddd.loseyourip.com
		$a_01_1 = {7b 36 3d 3a 7b 36 21 27 2d 36 3b 2c 74 3f 3d 38 38 74 79 6d 74 54 00 } //00 00 
	condition:
		any of ($a_*)
 
}