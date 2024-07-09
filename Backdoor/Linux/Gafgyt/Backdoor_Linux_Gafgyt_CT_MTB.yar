
rule Backdoor_Linux_Gafgyt_CT_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.CT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8f c4 00 50 00 60 28 ?? 24 06 00 0a 24 07 00 01 8f 82 80 24 00 00 00 00 24 59 0a d0 03 20 f8 09 00 } //1
		$a_03_1 = {a2 00 18 8f c4 00 50 00 60 ?? ?? 24 06 00 0a 24 07 00 01 8f 82 80 24 00 00 00 00 24 59 0a d0 03 20 f8 09 00 00 00 00 8f dc 00 20 8f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}