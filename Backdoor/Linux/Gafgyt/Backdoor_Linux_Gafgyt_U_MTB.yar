
rule Backdoor_Linux_Gafgyt_U_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.U!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f0 82 00 60 01 c2 27 bf f0 10 bf ff bc 01 00 00 00 9d e3 ?? 40 f0 27 a0 44 f2 27 a0 48 f4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}