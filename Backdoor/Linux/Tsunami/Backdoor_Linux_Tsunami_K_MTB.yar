
rule Backdoor_Linux_Tsunami_K_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.K!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {42 11 02 00 21 28 40 00 80 10 02 00 20 00 c3 27 21 10 43 00 44 04 44 8c 2c 00 c2 8f 00 } //1
		$a_00_1 = {8f c3 00 24 24 02 00 01 14 62 00 0d 00 00 00 00 a7 c0 00 08 27 c3 00 08 8f c2 00 20 00 00 00 00 90 42 00 00 00 00 00 00 a0 62 00 00 97 c2 00 08 8f c4 00 10 00 00 00 00 00 82 20 21 af c4 00 10 8f c2 00 10 00 00 00 00 00 02 1c 03 8f c4 00 10 00 00 00 00 30 82 ff ff 00 62 18 21 af c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}