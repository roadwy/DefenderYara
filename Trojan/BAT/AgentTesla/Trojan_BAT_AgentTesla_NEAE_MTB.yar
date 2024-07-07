
rule Trojan_BAT_AgentTesla_NEAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {34 33 39 37 34 39 30 62 2d 33 33 66 33 2d 34 65 65 61 2d 61 30 62 64 2d 35 62 61 34 37 35 64 62 31 38 62 64 } //5 4397490b-33f3-4eea-a0bd-5ba475db18bd
		$a_01_1 = {48 76 47 4a 6f 50 2e 4d 79 } //4 HvGJoP.My
		$a_01_2 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 2b 34 34 37 33 34 31 39 36 34 66 } //2 Confuser.Core 1.6.0+447341964f
		$a_01_3 = {50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 79 6c 65 } //1 ProcessWindowStyle
		$a_01_4 = {53 70 65 63 69 61 6c 46 6f 6c 64 65 72 } //1 SpecialFolder
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}