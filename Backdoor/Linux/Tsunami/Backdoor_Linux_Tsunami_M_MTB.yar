
rule Backdoor_Linux_Tsunami_M_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.M!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 10 21 00 02 10 40 00 82 20 23 af c4 04 34 8f c3 04 34 00 00 00 00 30 62 00 ff 24 42 } //1
		$a_00_1 = {24 02 00 01 00 62 10 04 00 82 20 25 00 05 10 80 27 c3 00 20 00 43 10 21 ac 44 04 44 24 02 00 3c af c2 04 60 } //1
		$a_00_2 = {ff d4 80 1f 00 14 54 00 d9 7e 7c 0a 03 78 54 09 10 3a 38 1f 00 08 7d 29 02 14 39 29 04 44 81 69 00 00 80 1f 00 14 54 09 06 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}