
rule Ransom_Linux_Deadbolt_B_MTB{
	meta:
		description = "Ransom:Linux/Deadbolt.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 7c 24 08 48 c7 c6 03 00 00 00 48 c7 c2 00 00 00 00 b8 48 00 00 00 0f 05 8b 7c 24 08 48 c7 c6 04 00 00 00 48 c7 c2 00 08 00 00 09 c2 b8 48 00 00 00 0f 05 c3 } //1
		$a_01_1 = {83 ff 1b 75 f6 b8 00 00 00 00 b9 01 00 00 00 4c 8d 1d aa ee 2b 00 f0 41 0f b1 0b 75 de 48 8b 0d cc e7 28 00 4c 8d 05 75 f9 2b 00 4c 8d 0d ce 08 00 00 48 8b 05 cf e6 28 00 ff e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}