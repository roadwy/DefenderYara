
rule Trojan_Linux_Mirai_C_MTB{
	meta:
		description = "Trojan:Linux/Mirai.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 6c 75 6d 69 2f 66 6d 77 2e 70 68 70 3f 63 3d } //01 00 
		$a_01_1 = {2f 76 61 72 2f 74 6d 70 2f 64 6e 73 73 6d 61 73 71 } //01 00 
		$a_01_2 = {6d 6f 70 73 } //01 00 
		$a_01_3 = {2f 75 73 72 2f 62 69 6e 2f 64 6e 73 73 6d 61 73 71 } //00 00 
	condition:
		any of ($a_*)
 
}