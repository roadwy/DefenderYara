
rule Backdoor_Linux_Mirai_HY_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HY!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 fe 01 77 ee 75 08 48 0f be 07 ?? ?? ?? ?? 48 0f b7 d1 48 c1 e9 10 48 01 ca 48 89 d0 48 c1 e8 10 48 01 d0 f7 d0 0f b7 c0 c3 } //1
		$a_00_1 = {41 55 41 89 d5 41 54 45 31 e4 55 53 48 83 ec 08 8b 5f 0c 8b 6f 10 eb 0d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}