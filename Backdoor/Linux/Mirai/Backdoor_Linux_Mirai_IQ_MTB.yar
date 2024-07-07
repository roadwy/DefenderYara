
rule Backdoor_Linux_Mirai_IQ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 c9 08 20 44 90 01 01 54 e0 fe 06 b6 36 18 90 01 01 09 e7 63 61 c0 71 1f 52 28 22 13 90 01 01 e3 60 85 d6 0a e3 90 00 } //1
		$a_00_1 = {48 e0 00 42 2a 32 5d d0 23 61 8a 21 28 31 ae 96 13 65 00 45 13 64 fc 36 0b 40 5a 35 a8 91 fc 31 13 62 08 32 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}