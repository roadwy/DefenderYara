
rule Backdoor_Linux_Mirai_DO_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 51 20 21 ?? 62 00 00 ?? ?? ?? ?? 38 42 00 37 a0 62 00 00 24 63 00 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}