
rule Backdoor_Linux_Mirai_HX_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HX!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {85 2c 20 08 a0 10 80 01 03 03 42 83 82 10 61 0a 80 a4 00 01 12 bf ff f2 92 07 bf f7 } //1
		$a_00_1 = {90 10 00 11 92 10 00 10 7f ff ff 94 94 10 20 80 80 a2 20 00 04 80 00 07 94 10 00 08 } //1
		$a_00_2 = {94 10 20 01 7f ff ff a6 90 10 00 11 80 a2 20 01 02 80 00 05 c2 4f bf f7 } //1
		$a_00_3 = {92 07 bf e4 7f ff ff ad 94 10 20 10 a0 92 20 00 36 80 00 0a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}