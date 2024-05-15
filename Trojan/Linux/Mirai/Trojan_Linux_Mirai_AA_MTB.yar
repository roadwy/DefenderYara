
rule Trojan_Linux_Mirai_AA_MTB{
	meta:
		description = "Trojan:Linux/Mirai.AA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 04 00 "
		
	strings :
		$a_00_0 = {b8 42 00 00 00 cd 80 89 c2 81 fa 00 f0 ff ff 76 0d b8 f8 ff ff ff f7 da 65 89 10 83 c8 ff } //04 00 
		$a_00_1 = {8b 54 24 04 31 c0 80 3a 00 74 0e 90 8d 74 26 00 83 c0 01 80 3c 10 00 75 f7 f3 c3 } //01 00 
		$a_00_2 = {54 43 50 5c 72 71 4d 44 4b 43 } //01 00  TCP\rqMDKC
		$a_00_3 = {6c 63 6f 67 71 67 70 74 67 70 } //01 00  lcogqgptgp
		$a_00_4 = {70 6f 73 74 20 2f 63 64 6e 2d 63 67 69 2f } //00 00  post /cdn-cgi/
	condition:
		any of ($a_*)
 
}