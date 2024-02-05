
rule Trojan_Linux_Mirai_FA{
	meta:
		description = "Trojan:Linux/Mirai.FA,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {44 44 6f 53 2d 41 74 74 61 63 6b } //DDoS-Attack  01 00 
		$a_80_1 = {42 4f 54 4b 49 4c 4c } //BOTKILL  00 00 
	condition:
		any of ($a_*)
 
}