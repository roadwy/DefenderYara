
rule Trojan_Linux_Mirai_A_MTB{
	meta:
		description = "Trojan:Linux/Mirai.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {03 10 c0 e3 04 20 91 e4 03 30 10 e2 00 00 63 e2 04 00 00 0a ff 20 82 e3 01 30 53 e2 ff 2c 82 c3 01 30 53 e2 ff 28 82 c3 ff 00 12 e3 ff 0c 12 13 ff 08 12 13 ff 04 12 13 04 00 80 12 04 20 91 14 f8 ff ff 1a ff 00 12 e3 01 00 80 12 ff 0c 12 13 01 00 80 12 ff 08 12 13 01 00 80 12 0e f0 a0 e1 } //02 00 
		$a_00_1 = {46 55 43 4b 54 2f } //00 00 
	condition:
		any of ($a_*)
 
}