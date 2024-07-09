
rule Backdoor_Linux_Mirai_HM_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {98 88 99 8f 50 00 a5 8f 21 20 c0 02 09 f8 20 03 10 00 06 24 20 00 bc 8f 0a 00 02 24 28 00 a4 8f 50 81 99 8f 08 00 62 ae 10 00 02 24 00 00 71 ae 0c 00 62 ae 09 f8 20 03 10 00 77 ae 20 00 bc 8f 21 20 00 00 a4 00 a2 8f } //1
		$a_03_1 = {18 00 c3 00 98 80 99 8f 24 00 44 26 12 30 00 00 09 f8 20 03 21 28 20 02 60 00 a2 8f 4c 00 a3 8f 20 00 bc 8f 18 00 43 00 12 10 00 00 21 a0 22 02 00 00 92 ae 60 00 a2 8f 09 ?? ?? ?? ff ff 43 24 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}