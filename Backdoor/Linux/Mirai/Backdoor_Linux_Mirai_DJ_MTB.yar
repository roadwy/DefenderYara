
rule Backdoor_Linux_Mirai_DJ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DJ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 76 61 72 2f 43 6f 6e 64 69 42 6f 74 } //01 00  /var/CondiBot
		$a_01_1 = {62 6f 61 74 6e 65 74 } //01 00  boatnet
		$a_03_2 = {2f 62 69 6e 2f 7a 68 74 74 70 64 2f 90 01 06 63 64 90 01 06 2f 74 6d 70 3b 90 01 06 72 6d 90 01 06 2d 72 66 90 01 06 2a 3b 90 01 06 77 67 65 74 90 01 06 68 74 74 70 3a 2f 2f 90 02 15 2f 6d 69 70 73 3b 90 01 06 63 68 6d 6f 64 90 00 } //01 00 
		$a_01_3 = {2f 74 6d 70 2f 63 6f 6e 64 69 6e 65 74 77 6f 72 6b } //00 00  /tmp/condinetwork
	condition:
		any of ($a_*)
 
}