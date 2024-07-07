
rule Backdoor_Linux_Mirai_FS_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {95 31 20 08 9a 10 40 0d 99 36 20 08 92 53 40 1a 91 40 00 00 85 3e a0 1f 96 82 40 0a 82 5b 00 1a 84 58 80 0d 82 00 40 02 90 01 01 00 40 08 03 00 3f ff 94 42 20 00 82 10 63 ff 80 a2 80 01 90 00 } //1
		$a_03_1 = {d4 22 60 08 80 a2 a0 00 02 90 01 03 d6 22 60 04 10 90 01 03 d2 22 a0 04 d2 22 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}