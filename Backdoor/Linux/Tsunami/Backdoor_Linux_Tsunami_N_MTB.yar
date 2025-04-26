
rule Backdoor_Linux_Tsunami_N_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.N!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 d5 8e ff ff 85 c0 75 27 48 8b 33 48 8b 7d 00 e8 c5 8e ff ff 85 c0 75 17 48 8b 73 10 48 8b 7d 10 e8 b4 8e ff ff 85 c0 75 06 8b 45 08 2b 43 08 } //1
		$a_01_1 = {41 8b 7e 18 48 d1 eb 49 8b 36 8b 44 d8 04 85 ff 74 04 0f c8 89 c0 48 01 c6 4c 89 ef e8 a2 8c ff ff 85 c0 78 3e 85 c0 74 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}