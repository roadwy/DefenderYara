
rule Backdoor_Linux_Mirai_EI_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EI!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 65 61 72 64 72 6f 70 70 65 72 } //1 beardropper
		$a_01_1 = {74 30 74 61 6c 63 30 6e 74 72 30 6c 34 21 } //1 t0talc0ntr0l4!
		$a_01_2 = {80 a0 7f ff 12 80 00 11 c4 07 bf dc 40 00 01 3b 01 00 00 00 40 00 01 19 a0 10 00 08 80 a4 00 08 12 80 00 15 90 10 20 00 40 00 01 24 01 00 00 00 40 00 01 02 a0 10 00 08 80 a4 00 08 12 80 00 0e 90 10 20 00 c4 07 bf dc 80 a0 bf ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}