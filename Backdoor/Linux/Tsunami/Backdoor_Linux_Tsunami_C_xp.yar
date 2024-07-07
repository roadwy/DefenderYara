
rule Backdoor_Linux_Tsunami_C_xp{
	meta:
		description = "Backdoor:Linux/Tsunami.C!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 51 52 49 51 52 4c 51 52 4c 51 52 41 51 52 4c 51 52 4c } //1 KQRIQRLQRLQRAQRLQRL
		$a_01_1 = {43 51 52 48 51 52 45 51 52 43 51 52 4b 51 52 53 51 52 55 51 52 4d } //1 CQRHQREQRCQRKQRSQRUQRM
		$a_01_2 = {47 51 52 45 51 52 54 51 52 53 51 52 50 51 52 4f 51 52 4f 51 52 46 51 52 53 } //1 GQREQRTQRSQRPQROQROQRFQRS
		$a_01_3 = {55 51 52 44 51 52 50 } //1 UQRDQRP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}