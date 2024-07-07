
rule Backdoor_Linux_Gafgyt_CC_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CC!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {40 19 00 00 a6 90 12 20 34 96 12 e0 94 98 13 20 d8 9a 10 00 01 40 00 54 87 01 } //1
		$a_00_1 = {24 00 01 a5 90 00 01 a7 34 00 01 a9 88 00 01 aa 5c 00 01 ae 94 00 01 b1 54 00 01 b5 44 00 01 b6 b0 00 01 b7 60 00 01 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}