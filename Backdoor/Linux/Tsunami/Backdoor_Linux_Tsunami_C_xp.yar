
rule Backdoor_Linux_Tsunami_C_xp{
	meta:
		description = "Backdoor:Linux/Tsunami.C!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 51 52 49 51 52 4c 51 52 4c 51 52 41 51 52 4c 51 52 4c } //01 00  KQRIQRLQRLQRAQRLQRL
		$a_01_1 = {43 51 52 48 51 52 45 51 52 43 51 52 4b 51 52 53 51 52 55 51 52 4d } //01 00  CQRHQREQRCQRKQRSQRUQRM
		$a_01_2 = {47 51 52 45 51 52 54 51 52 53 51 52 50 51 52 4f 51 52 4f 51 52 46 51 52 53 } //01 00  GQREQRTQRSQRPQROQROQRFQRS
		$a_01_3 = {55 51 52 44 51 52 50 } //00 00  UQRDQRP
		$a_00_4 = {5d 04 00 } //00 a7 
	condition:
		any of ($a_*)
 
}