
rule Backdoor_Linux_Mirai_CP_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CP!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {90 0a 20 ff 05 00 00 bc 91 2a 20 03 90 02 00 01 c2 12 20 04 80 a0 60 00 04 80 00 1c c4 00 a0 c4 95 30 a0 18 96 10 00 02 99 30 a0 08 9b 30 a0 10 88 10 20 00 c4 02 00 00 } //1
		$a_00_1 = {c2 09 00 02 82 18 40 0b c2 29 00 02 c6 02 00 00 c2 09 00 03 82 18 40 0c c2 29 00 03 c4 02 00 00 c2 09 00 02 82 18 40 0d c2 29 00 02 c6 02 00 00 c2 09 00 03 82 18 40 0a c2 29 00 03 88 01 20 01 c2 12 20 04 80 a0 40 04 34 bf ff ee } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}