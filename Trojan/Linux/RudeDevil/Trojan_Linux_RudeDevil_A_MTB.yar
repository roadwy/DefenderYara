
rule Trojan_Linux_RudeDevil_A_MTB{
	meta:
		description = "Trojan:Linux/RudeDevil.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f } //1 stratum+tcp://
		$a_00_1 = {6d 20 6e 6f 74 20 72 75 64 65 20 61 74 20 61 6c 6c } //1 m not rude at all
		$a_00_2 = {8b 45 f8 48 3b 45 e0 73 2d 48 8b 45 e8 0f b6 00 2a 45 f7 89 c2 48 8b 45 e8 88 10 48 8b 45 e8 48 8d 50 01 48 89 55 e8 0f b6 10 32 55 f7 88 10 48 83 45 f8 01 eb c9 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}