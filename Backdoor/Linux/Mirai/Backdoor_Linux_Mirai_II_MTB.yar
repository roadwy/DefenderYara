
rule Backdoor_Linux_Mirai_II_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.II!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 ff 05 31 08 00 e0 03 01 00 02 24 02 22 08 00 00 ff 84 30 00 2a 05 00 02 1e 08 00 00 16 08 00 25 10 45 00 25 18 64 00 25 18 62 00 01 00 02 24 08 00 e0 03 00 00 63 ad } //1
		$a_01_1 = {14 00 84 90 02 1e 10 00 02 2a 05 00 00 32 06 00 00 86 10 00 25 18 65 00 25 80 06 02 06 10 82 00 25 18 70 00 21 18 62 00 24 38 67 00 00 ff 64 30 02 16 03 00 02 3a 07 00 00 22 04 00 00 1e 03 00 25 10 47 00 25 18 64 00 25 10 43 00 18 00 bc 8f 10 00 22 ae } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}