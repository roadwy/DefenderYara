
rule Backdoor_Linux_Mirai_EW_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3c 00 cc cc 7d 23 48 50 60 00 cc cd 7d 29 01 d6 7f 4b d3 78 39 40 00 00 } //1
		$a_03_1 = {1c 19 ff fb 3a e0 00 00 7d 3d 02 14 2f 89 00 06 41 90 01 03 8a c7 00 06 2f 96 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}