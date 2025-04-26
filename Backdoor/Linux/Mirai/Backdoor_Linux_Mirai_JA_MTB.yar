
rule Backdoor_Linux_Mirai_JA_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7c 1d 58 50 7c 7f ea 14 60 00 00 01 63 a9 00 01 90 03 00 04 38 63 00 08 7d 3f e9 2e 91 3f 00 04 7c 1f 59 2e } //1
		$a_01_1 = {81 5e 00 0c 7d 3e 8a 14 80 1e 00 08 7f df f3 78 91 09 00 04 90 09 00 08 62 20 00 01 91 2a 00 08 91 49 00 0c 81 69 00 08 7c 1e 89 2e 90 1e 00 04 91 2b 00 0c 7d 07 f1 2e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}