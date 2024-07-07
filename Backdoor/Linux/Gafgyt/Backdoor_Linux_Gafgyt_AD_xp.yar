
rule Backdoor_Linux_Gafgyt_AD_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AD!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 51 52 49 51 52 4c 51 52 4c 51 52 41 51 52 54 51 52 54 51 52 4b } //1 KQRIQRLQRLQRAQRTQRTQRK
		$a_01_1 = {4c 51 52 4f 51 52 4c 51 52 4e 51 52 4f 51 52 47 51 52 54 51 52 46 51 52 4f } //1 LQROQRLQRNQROQRGQRTQRFQRO
		$a_01_2 = {55 51 52 44 51 52 50 } //1 UQRDQRP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}