
rule Backdoor_Linux_Mirai_EV_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EV!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ba 40 42 0f 00 89 f8 48 83 ec 18 89 d1 31 d2 48 89 e7 f7 f1 31 f6 89 d2 89 c0 48 69 d2 e8 03 00 00 48 89 04 24 48 89 54 24 08 } //1
		$a_03_1 = {48 89 fe e8 0a 09 00 00 89 c5 85 ed 74 ?? 31 c0 48 81 bc 24 a8 01 00 00 ff 64 cd 1d 0f 9f c0 03 84 24 a0 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}